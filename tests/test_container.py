"""Optional Docker lifecycle/namespace check. Uses fake credentials; never logs in."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
import uuid

IMAGE = os.environ.get("VPN_CONTAINER_IMAGE")


def available_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


@unittest.skipUnless(IMAGE, "Set VPN_CONTAINER_IMAGE to test a built Docker image")
class ContainerTests(unittest.TestCase):
    def test_passive_start_route_isolation_and_restart(self):
        def docker(*args):
            try:
                return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.STDOUT).strip()
            except subprocess.CalledProcessError as error:
                error.add_note(error.output)
                raise
        with tempfile.TemporaryDirectory(prefix="vpn-router-container-test-") as directory:
            root = Path(directory)
            data, health = root / "data", root / "health"
            (data / "runtime").mkdir(parents=True)
            # Linux bind mounts keep the host UID. This disposable fake-data
            # directory must be writable by container root without DAC_OVERRIDE.
            # Docker Desktop translates Windows ACLs, so it needs no adjustment.
            if os.name == "posix":
                (data / "runtime").chmod(0o777)
            health.mkdir()
            api_port, relay_port = available_port(), available_port()
            token = "a" * 64
            (data / "runtime/api.token").write_text(token)
            (data / "runtime/relay.key").write_text("b" * 64)
            (data / "config.toml").write_text(f'[vpn]\nhost="vpn.invalid"\nuser="fake"\npassword="fake"\n[docker]\napi_port={api_port}\nrelay_port={relay_port}\n[routing]\nmode="direct-default"\n')
            (health / "status.json").write_text(json.dumps({"active": False, "updated": time.time()}))
            name = "vpn-router-validation-" + uuid.uuid4().hex[:12]
            opener = build_opener(ProxyHandler({}))
            def status(authorized=True):
                headers = {"Authorization": "Bearer " + token} if authorized else {}
                with opener.open(Request(f"http://127.0.0.1:{api_port}/api/status", headers=headers), timeout=2) as response:
                    return json.load(response)
            def wait_ready():
                for _ in range(50):
                    try:
                        return status()
                    except OSError:
                        time.sleep(.2)
                self.fail("Container control API did not become ready")
            created = False
            try:
                docker("run", "-d", "--name", name, "--label", "vpn-router.validation=" + name,
                       "--restart=no", "--init", "--read-only", "--tmpfs", "/tmp",
                       "--cap-drop=ALL", "--cap-add=NET_ADMIN", "--device=/dev/net/tun", "--security-opt=no-new-privileges:true",
                       "--mount", f"type=bind,source={data},target=/data",
                       "--mount", f"type=bind,source={health},target=/router-status,readonly",
                       "-p", f"127.0.0.1:{api_port}:{api_port}/tcp",
                       "-p", f"127.0.0.1:{relay_port}:{relay_port}/tcp",
                       "-p", f"127.0.0.1:{relay_port}:{relay_port}/udp", IMAGE)
                created = True
                initial = wait_ready()
                self.assertEqual(initial["connection_state"], "disconnected")
                self.assertEqual(initial["oc_pid"], 0)
                self.assertFalse(initial["auto_reconnect"])
                update = health / "status.tmp"
                update.write_text(json.dumps({"active": True, "updated": time.time()}))
                update.replace(health / "status.json")
                self.assertTrue(status()["router_active"], "Mounted native health must reflect atomic updates")
                with self.assertRaises(HTTPError) as error:
                    status(False)
                self.assertEqual(error.exception.code, 401)
                before_resolver = docker("exec", name, "cat", "/etc/resolv.conf")
                before_route = docker("exec", name, "ip", "route", "show", "default")
                # Exercise the real executable hook/device without contacting any VPN.
                docker("exec", "-e", "reason=pre-init", name, "/app/vpnc-script.py")
                docker("exec", name, "ip", "tuntap", "add", "dev", "tun0", "mode", "tun")
                docker("exec", "-e", "reason=connect", "-e", "VPNGATEWAY=203.0.113.10",
                       "-e", "INTERNAL_IP4_ADDRESS=10.77.0.2", "-e", "INTERNAL_IP4_DNS=10.77.0.53",
                       "-e", "INTERNAL_IP6_ADDRESS=2001:db8::2/64", name, "/app/vpnc-script.py")
                self.assertIn("dev tun0", docker("exec", name, "ip", "route", "show", "default"))
                self.assertEqual(before_resolver, docker("exec", name, "cat", "/etc/resolv.conf"))
                self.assertEqual(status()["connection_state"], "disconnected", "Control API must stay reachable after container route changes")
                docker("exec", "-e", "reason=disconnect", name, "/app/vpnc-script.py")
                self.assertEqual(before_route, docker("exec", name, "ip", "route", "show", "default"))
                docker("exec", name, "ip", "link", "delete", "tun0")
                # Exercise the synchronous reconnect veto with a sacrificial
                # Linux process named openconnect; it performs no network I/O.
                veto = ('import ctypes,os,subprocess; '
                        'ctypes.CDLL(None).prctl(15,b"openconnect",0,0,0); '
                        'subprocess.run(["/app/vpnc-script.py"],check=True); '
                        'print("returned to reconnect")')
                with self.assertRaises(subprocess.CalledProcessError) as blocked:
                    docker("exec", "-e", "reason=attempt-reconnect", "-e", "VPN_ALLOW_RECONNECT=0",
                           name, "python3", "-c", veto)
                self.assertEqual(blocked.exception.returncode, 137)
                self.assertNotIn("returned to reconnect", blocked.exception.output)
                allowed = docker("exec", "-e", "reason=attempt-reconnect", "-e", "VPN_ALLOW_RECONNECT=1",
                                 name, "python3", "-c", veto)
                self.assertIn("returned to reconnect", allowed)
                docker("restart", name)
                restarted = wait_ready()
                self.assertEqual(restarted["connection_state"], "disconnected")
                self.assertEqual(restarted["oc_pid"], 0)
                self.assertEqual(restarted["relay_pid"], 0)
            finally:
                if created:
                    owner = docker("inspect", "--format", '{{index .Config.Labels "vpn-router.validation"}}', name)
                    if owner != name:
                        raise RuntimeError("Refusing to remove an unowned validation container")
                    docker("rm", "-f", name)
