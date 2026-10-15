import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

TEST_ROOT = tempfile.TemporaryDirectory()
os.environ["VPN_DATA_DIR"] = TEST_ROOT.name
spec = importlib.util.spec_from_file_location("vpnctl", Path(__file__).parents[1] / "vpnctl.py")
daemon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daemon)
hook_spec = importlib.util.spec_from_file_location("vpn_hook", Path(__file__).parents[1] / "vpnc-script.py")
hook = importlib.util.module_from_spec(hook_spec)
hook_spec.loader.exec_module(hook)


class DaemonTests(unittest.TestCase):
    def setUp(self):
        daemon.CANCEL.clear()
        daemon.AUTH = daemon.TUNNEL = daemon.RELAY = daemon.WORKER = None
        daemon.STATE.update(connection_state="disconnected", oc_pid=0, relay_pid=0, error="")
        daemon.CONFIG_PATH.write_text('[vpn]\nhost="vpn.example"\nuser="user"\npassword="p#ass"\n[docker]\napi_port=8889\n[routing]\nmode="direct-default"\n')
        (daemon.RUNTIME / "api.token").write_text("a" * 64)
        (daemon.RUNTIME / "relay.key").write_text("b" * 64)

    def test_container_restart_is_passive(self):
        previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        try:
            with patch.object(daemon, "ThreadingHTTPServer") as server, patch.object(daemon, "connect") as connect, patch.object(daemon.subprocess, "Popen") as popen:
                daemon.main()
                connect.assert_not_called()
                popen.assert_not_called()
                server.return_value.serve_forever.assert_called_once()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)

    def test_retry_default_and_no_reauthentication_credentials(self):
        vpn = daemon.load_config()["vpn"]
        args = daemon.tunnel_command(vpn, {"COOKIE": "secret-cookie"})
        self.assertIn("--reconnect-timeout=0", args)
        self.assertIn("--no-passwd", args)
        self.assertIn("--non-inter", args)
        self.assertIn("--script=exec /app/vpnc-script.py", args)
        self.assertNotIn("p#ass", " ".join(args))
        self.assertNotIn("secret-cookie", " ".join(args))
        vpn["auto_reconnect"] = True
        self.assertIn("--reconnect-timeout=300", daemon.tunnel_command(vpn, {}))

    def test_hook_blocks_first_transport_reconnect_unless_enabled(self):
        with patch.dict(os.environ, {"reason": "attempt-reconnect", "VPN_ALLOW_RECONNECT": "0"}), patch.object(hook.os, "getppid", return_value=123), patch.object(hook.Path, "read_text", return_value="openconnect\n"), patch.object(hook.os, "kill") as kill:
            hook.main()
            kill.assert_called_once_with(123, 9)
        with patch.dict(os.environ, {"reason": "attempt-reconnect", "VPN_ALLOW_RECONNECT": "1"}), patch.object(hook.os, "kill") as kill:
            hook.main()
            kill.assert_not_called()
        with patch.dict(os.environ, {"reason": "attempt-reconnect", "VPN_ALLOW_RECONNECT": "0"}), patch.object(hook.Path, "read_text", return_value="unrelated\n"), patch.object(hook.os, "kill") as kill:
            with self.assertRaises(RuntimeError):
                hook.main()
            kill.assert_not_called()

    def test_failed_authentication_is_never_retried(self):
        process = Mock(returncode=1)
        process.communicate.return_value = ("", None)
        with patch.object(daemon.subprocess, "Popen", return_value=process) as popen, patch.object(daemon, "stop_process"):
            daemon.connect_worker()
            self.assertEqual(popen.call_count, 1)
            self.assertEqual(daemon.STATE["connection_state"], "disconnected")
            self.assertIn("declined", daemon.STATE["error"])

    def test_authentication_timeout_is_never_retried(self):
        process = Mock()
        process.communicate.side_effect = subprocess.TimeoutExpired("openconnect", 90)
        with patch.object(daemon.subprocess, "Popen", return_value=process) as popen, patch.object(daemon, "stop_process"):
            daemon.connect_worker()
            self.assertEqual(popen.call_count, 1)
            self.assertIn("timed out", daemon.STATE["error"])

    def test_duplicate_connect_does_not_duplicate_mfa(self):
        with patch.object(daemon.threading, "Thread") as thread:
            thread.return_value.is_alive.return_value = True
            daemon.connect()
            daemon.connect()
            thread.assert_called_once()
            thread.return_value.start.assert_called_once()

    def test_cookie_output_is_parsed_without_shell_execution(self):
        session = daemon.parse_session("COOKIE='a; $(danger)'\nHOST='vpn.example'\nIGNORED='anything'\n")
        self.assertEqual(session, {"COOKIE": "a; $(danger)", "HOST": "vpn.example"})

    def test_config_preserves_hash_password_and_rejects_truthy_string(self):
        daemon.update_config({"routing": {"mode": "vpn-default"}})
        self.assertEqual(daemon.load_config()["vpn"]["password"], "p#ass")
        with self.assertRaises(ValueError):
            daemon.update_config({"vpn": {"auto_reconnect": "false"}})
        with self.assertRaises(ValueError):
            daemon.update_config({"vpn": {"dns_server": "not-an-ip"}})
        self.assertNotIn("password", daemon.read_config_for_api()["vpn"])
        daemon.update_config({"vpn": {"password": "p#ass\U0001f512"}})
        self.assertEqual(daemon.load_config()["vpn"]["password"], "p#ass\U0001f512")

    def test_relay_binds_dns_and_egress_to_vpn_interface(self):
        cfg = daemon.relay_config({}, {"dns": ["10.0.0.53"]})
        self.assertEqual(cfg["outbounds"][0]["bind_interface"], "tun0")
        self.assertEqual(cfg["dns"]["servers"][0]["bind_interface"], "tun0")
        self.assertNotIn("network", cfg["inbounds"][0])
        with self.assertRaises(ValueError):
            daemon.relay_config({}, {})
        fixture = os.environ.get("VPN_RELAY_CONFIG_FIXTURE")
        if fixture:
            Path(fixture).write_text(json.dumps(cfg))

    def test_url_input_routes_host(self):
        self.assertEqual(daemon.normalize_entry("https://Corp.Example/path"), "corp.example")
        self.assertEqual(daemon.normalize_entry("10.1.2.3/16"), "10.1.0.0/16")
        with self.assertRaises(ValueError):
            daemon.normalize_entry("corp.example/path")

    def test_http_auth_and_cross_origin_requests_cannot_connect(self):
        server = daemon.ThreadingHTTPServer(("127.0.0.1", 0), daemon.Handler)
        port = server.server_address[1]
        with daemon.CONFIG_PATH.open("a") as cfg:
            cfg.write(f"\n[docker_test_unused]\nport={port}\n")
        text = daemon.CONFIG_PATH.read_text().replace("api_port=8889", f"api_port={port}")
        daemon.CONFIG_PATH.write_text(text)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.object(daemon, "connect") as connect:
                for headers, expected in (({}, 401), ({"Authorization": "Bearer " + "a" * 64, "Origin": "https://evil.example"}, 403), ({"Authorization": "Bearer " + "a" * 64, "Host": "evil.example"}, 403)):
                    request = Request(f"http://127.0.0.1:{port}/api/connect", data=b"{}", headers=headers)
                    with self.assertRaises(HTTPError) as error:
                        urlopen(request, timeout=3)
                    self.assertEqual(error.exception.code, expected)
                connect.assert_not_called()
                request = Request(f"http://127.0.0.1:{port}/api/connect", data=b"{}", headers={"Authorization": "Bearer " + "a" * 64})
                with urlopen(request, timeout=3) as response:
                    self.assertEqual(response.status, 202)
                connect.assert_called_once()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
