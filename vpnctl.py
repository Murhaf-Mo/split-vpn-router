#!/usr/bin/env python3
"""Docker VPN daemon. Only an explicit POST /api/connect authenticates."""
import contextlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import threading
import time
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

INSTALL_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("VPN_DATA_DIR", "/data"))
RUNTIME = DATA_DIR / "runtime"
RUNTIME.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "config.toml"
LOG_PATHS = {name: RUNTIME / (name + ".log") for name in ("oc", "pac", "proxy")}
LOCK = threading.RLock()
STATE = {"connection_state": "disconnected", "error": "", "oc_pid": 0, "relay_pid": 0}
TUNNEL = AUTH = RELAY = None
CANCEL = threading.Event()
WORKER = None


def event(message):
    text = time.strftime("[%H:%M:%S] ") + str(message)
    with contextlib.suppress(OSError):
        print(text, flush=True)
        with LOG_PATHS["pac"].open("a", encoding="utf-8") as stream:
            stream.write(text + "\n")


def load_config():
    with CONFIG_PATH.open("rb") as stream:
        return tomllib.load(stream)


def entries(which):
    path = DATA_DIR / (which + ".list")
    if not path.exists():
        return []
    return [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.split("#", 1)[0].strip()]


def normalize_entry(value):
    """A URL selects its host. Encrypted HTTPS paths cannot be packet-routing rules."""
    value = value.strip().lower()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Use an HTTP(S) URL, domain, IP address or CIDR")
        value = parsed.hostname
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        if not value or any(c in value for c in "/\\\n\r\t #:@"):
            raise ValueError("Invalid routing entry; use a full HTTP(S) URL for URL input")
        return value


def read_config_for_api():
    cfg = load_config()
    vpn = cfg.get("vpn", {})
    return {"vpn": {k: vpn.get(k, "") for k in ("host", "user", "group", "dns_server")} | {
                "password_set": bool(vpn.get("password")), "auto_reconnect": vpn.get("auto_reconnect", False)},
            "routing": {"mode": cfg.get("routing", {}).get("mode", "direct-default")},
            "docker": {"api_port": cfg.get("docker", {}).get("api_port", 8889),
                       "relay_port": cfg.get("docker", {}).get("relay_port", 1080)}}


def serialize_config(cfg):
    lines = ["# Docker VPN router configuration; contains your VPN password."]
    for section, values in cfg.items():
        if section in ("wsl", "proxy"):
            continue
        lines.extend(["", "[" + section + "]"])
        for key, value in values.items():
            if not key.replace("_", "").isalnum():
                raise ValueError("Invalid configuration key")
            lines.append(key + " = " + json.dumps(value, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def update_config(body):
    with LOCK:
        cfg = load_config()
        for section, allowed in {"vpn": ("host", "user", "password", "group", "dns_server", "auto_reconnect"),
                                 "routing": ("mode",)}.items():
            values = body.get(section, {})
            if not isinstance(values, dict):
                raise ValueError("Configuration sections must be objects")
            for key in allowed:
                if key in values and (key != "password" or values[key]):
                    if key == "auto_reconnect":
                        if not isinstance(values[key], bool):
                            raise ValueError("auto_reconnect must be true or false")
                    elif not isinstance(values[key], str):
                        raise ValueError(key + " must be a string")
                    cfg.setdefault(section, {})[key] = values[key]
        if cfg.get("routing", {}).get("mode", "direct-default") not in ("vpn-default", "direct-default"):
            raise ValueError("Invalid routing mode")
        for key in ("host", "user", "password"):
            if not isinstance(cfg.get("vpn", {}).get(key), str) or not cfg["vpn"][key].strip():
                raise ValueError("vpn." + key + " is required")
        if cfg["vpn"].get("dns_server"):
            try:
                ipaddress.ip_address(cfg["vpn"]["dns_server"])
            except ValueError:
                raise ValueError("vpn.dns_server must be a corporate DNS IP address") from None
        temporary = CONFIG_PATH.with_suffix(".tmp")
        temporary.write_text(serialize_config(cfg), encoding="utf-8")
        temporary.replace(CONFIG_PATH)
        return read_config_for_api()


def stop_process(proc):
    if proc is None or proc.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


def restore_container_network():
    if (RUNTIME / "original-route.json").exists():
        env = dict(os.environ, reason="disconnect")
        subprocess.run(["/app/vpnc-script.py"], env=env, check=False)


def disconnect():
    global TUNNEL, RELAY
    CANCEL.set()
    # Stop children before joining the worker, but never join while holding LOCK.
    with LOCK:
        stop_process(AUTH)
        stop_process(RELAY)
        stop_process(TUNNEL)
        restore_container_network()
    worker = WORKER
    if worker and worker is not threading.current_thread():
        worker.join(timeout=10)
    with LOCK:
        TUNNEL = RELAY = None
        STATE.update(connection_state="disconnected", oc_pid=0, relay_pid=0, error="")


def auth_command(vpn):
    args = ["openconnect", "--authenticate", "--non-inter", "--no-proxy", "--passwd-on-stdin",
            "--user=" + vpn["user"]]
    if vpn.get("group"):
        args.append("--authgroup=" + vpn["group"])
    return args + ["--", vpn["host"]]


def tunnel_command(vpn, session):
    # This process never receives the password. Expired cookies cannot trigger fresh MFA.
    args = ["openconnect", "--cookie-on-stdin", "--no-passwd", "--non-inter", "--no-proxy",
            "--interface=tun0", "--script=exec /app/vpnc-script.py",
            "--reconnect-timeout=" + ("300" if vpn.get("auto_reconnect", False) is True else "0")]
    for key, flag in (("FINGERPRINT", "--servercert="), ("RESOLVE", "--resolve=")):
        if session.get(key):
            args.append(flag + session[key])
    return args + ["--", session.get("CONNECT_URL") or session.get("HOST") or vpn["host"]]


def parse_session(output):
    session = {}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("COOKIE", "HOST", "CONNECT_URL", "RESOLVE", "FINGERPRINT"):
            words = shlex.split(value)
            if len(words) == 1:
                session[key] = words[0]
    if not session.get("COOKIE"):
        raise ValueError("Authentication did not return a session cookie; reconnect manually")
    return session


def relay_config(vpn, network):
    dns = vpn.get("dns_server") or next(iter(network.get("dns", [])), "")
    if not dns:
        raise ValueError("VPN did not provide DNS; set vpn.dns_server to your corporate DNS IP")
    ipaddress.ip_address(dns)
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "corp", "server": dns,
                              "bind_interface": "tun0"}], "final": "corp"},
        "inbounds": [{"type": "shadowsocks", "listen": "0.0.0.0",
                      "listen_port": load_config().get("docker", {}).get("relay_port", 1080),
                      "method": "chacha20-ietf-poly1305",
                      "password": (RUNTIME / "relay.key").read_text().strip()}],
        "outbounds": [{"type": "direct", "tag": "vpn", "bind_interface": "tun0",
                       "domain_resolver": "corp"}], "route": {"final": "vpn"}}


def connect_worker():
    global AUTH, TUNNEL, RELAY
    try:
        vpn = load_config()["vpn"]
        # Cookies stay in memory; never log authentication stdout or put secrets in argv.
        with LOG_PATHS["oc"].open("a", encoding="utf-8") as logfile:
            with LOCK:
                if CANCEL.is_set():
                    return
                AUTH = subprocess.Popen(auth_command(vpn), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=logfile, text=True,
                                        start_new_session=True)
                auth = AUTH
            try:
                output, _ = auth.communicate(vpn["password"] + "\n", timeout=90)
            except subprocess.TimeoutExpired:
                stop_process(auth)
                raise ValueError("Authentication timed out; reconnect manually")
            if CANCEL.is_set():
                return
            if auth.returncode:
                raise ValueError("Authentication failed or was declined; reconnect manually")
            session = parse_session(output)
            with LOCK:
                if CANCEL.is_set():
                    return
                AUTH = None
                TUNNEL = subprocess.Popen(tunnel_command(vpn, session), stdin=subprocess.PIPE,
                                          stdout=logfile, stderr=logfile, text=True, start_new_session=True,
                                          env={**os.environ, "VPN_ALLOW_RECONNECT": "1" if vpn.get("auto_reconnect", False) is True else "0"})
                TUNNEL.stdin.write(session.pop("COOKIE") + "\n")
                TUNNEL.stdin.close()
                STATE["oc_pid"] = TUNNEL.pid
            for _ in range(60):
                if CANCEL.wait(0.5):
                    return
                if TUNNEL.poll() is not None:
                    raise ValueError("VPN session ended; reconnect manually")
                if Path("/sys/class/net/tun0").exists() and (RUNTIME / "network.json").exists():
                    break
            else:
                raise ValueError("VPN tunnel did not become ready; reconnect manually")
            with LOCK:
                if CANCEL.is_set():
                    return
                network = json.loads((RUNTIME / "network.json").read_text())
                relay_path = RUNTIME / "relay.json"
                relay_path.write_text(json.dumps(relay_config(vpn, network)), encoding="utf-8")
                subprocess.run(["sing-box", "check", "-c", str(relay_path)], check=True,
                               stdout=logfile, stderr=logfile)
                with LOG_PATHS["proxy"].open("a") as relay_log:
                    RELAY = subprocess.Popen(["sing-box", "run", "-c", str(relay_path)],
                                             stdout=relay_log, stderr=relay_log, start_new_session=True)
                port = load_config().get("docker", {}).get("relay_port", 1080)
                for _ in range(50):
                    if RELAY.poll() is not None:
                        raise ValueError("VPN relay failed to start; inspect the relay log")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise ValueError("VPN relay did not become ready")
                STATE.update(connection_state="connected", relay_pid=RELAY.pid, error="")
            while not CANCEL.wait(1):
                if TUNNEL.poll() is not None or RELAY.poll() is not None:
                    raise ValueError("VPN session ended; reconnect manually (automatic login is disabled)")
    except Exception as error:
        event(error)
        with LOCK:
            stop_process(RELAY)
            stop_process(TUNNEL)
            restore_container_network()
            STATE.update(connection_state="disconnected", oc_pid=0, relay_pid=0, error=str(error))
    finally:
        with LOCK:
            AUTH = None


def connect():
    global WORKER
    with LOCK:
        if STATE["connection_state"] in ("connecting", "connected") or (WORKER and WORKER.is_alive()):
            return
        CANCEL.clear()
        (RUNTIME / "network.json").unlink(missing_ok=True)
        STATE.update(connection_state="connecting", error="")
        WORKER = threading.Thread(target=connect_worker, daemon=True)
        WORKER.start()


def build_status():
    with LOCK:
        status = dict(STATE)
    network = {}
    with contextlib.suppress(OSError, ValueError):
        network = json.loads((RUNTIME / "network.json").read_text())
    cfg = load_config()

    router_status = {}
    with contextlib.suppress(OSError, ValueError):
        router_status = json.loads(Path("/router-status/status.json").read_text())
    router_active = router_status.get("active", False) and time.time() - router_status.get("updated", 0) < 6
    status.update(router_active=router_active, router_error=router_status.get("error", ""))
    status.update(version=os.environ.get("VPN_VERSION", "dev"), mode=cfg.get("routing", {}).get("mode", "direct-default"),
                  runtime="docker", router="windows-tun", tun0_ip=network.get("address", "") if status["oc_pid"] else "",
                  proxy_host="127.0.0.1", proxy_port=cfg.get("docker", {}).get("relay_port", 1080),
                  daemon_pid=os.getpid(), auto_reconnect=cfg.get("vpn", {}).get("auto_reconnect", False))
    for which in ("vpn", "direct"):
        values = entries(which)
        status[which + "_list"] = {"domains": sum("/" not in e for e in values),
                                  "cidrs": sum("/" in e and "://" not in e for e in values),
                                  "urls": sum("://" in e for e in values)}
    return status


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, value, status=200, content_type="application/json"):
        data = (json.dumps(value) if content_type == "application/json" else value).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        port = load_config().get("docker", {}).get("api_port", 8889)
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in allowed:
            self.send({"error": "Invalid Host"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + host for host in allowed}:
            self.send({"error": "Invalid Origin"}, 403)
            return False
        if self.path.startswith("/api/"):
            expected = "Bearer " + (RUNTIME / "api.token").read_text().strip()
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected.encode()):
                self.send({"error": "Unauthorized"}, 401)
                return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        path = urlsplit(self.path).path
        if path == "/api/status":
            return self.send(build_status())
        if path == "/api/config":
            return self.send(read_config_for_api())
        if path == "/api/mode":
            return self.send({"mode": build_status()["mode"]})
        if path.startswith("/api/lists/") and path.rsplit("/", 1)[1] in ("vpn", "direct"):
            which = path.rsplit("/", 1)[1]
            return self.send({"list": which, "entries": entries(which)})
        if path.startswith("/api/logs/"):
            name = path.rsplit("/", 1)[1]
            if name in LOG_PATHS:
                text = ""
                if LOG_PATHS[name].exists():
                    with LOG_PATHS[name].open("rb") as stream:
                        stream.seek(0, 2)
                        stream.seek(max(0, stream.tell() - 50000))
                        text = stream.read().decode("utf-8", errors="replace")
                return self.send(text, content_type="text/plain; charset=utf-8")
        if path == "/":
            html = (INSTALL_DIR / "static/index.html").read_text(encoding="utf-8")
            return self.send(html, content_type="text/html; charset=utf-8")
        if path in ("/app.js", "/style.css"):
            mime = "text/javascript" if path.endswith("js") else "text/css"
            return self.send((INSTALL_DIR / "static" / path[1:]).read_text(encoding="utf-8"), content_type=mime)
        return self.send({"error": "Not found"}, 404)

    def do_POST(self):
        if not self.authorized():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 65536:
                raise ValueError("Request is too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            path = urlsplit(self.path).path
            if path == "/api/connect":
                connect()
                return self.send(build_status(), 202)
            if path == "/api/disconnect":
                disconnect()
                return self.send(build_status())
            if path == "/api/config":
                return self.send(update_config(body))
            if path == "/api/mode":
                update_config({"routing": {"mode": body.get("mode")}})
                return self.send({"mode": build_status()["mode"]})
            if path == "/api/reload":
                return self.send({"ok": True})
            if path.startswith("/api/lists/") and path.rsplit("/", 1)[1] in ("vpn", "direct"):
                which = path.rsplit("/", 1)[1]
                for field in ("add", "remove"):
                    values = body.get(field, [])
                    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                        raise ValueError(field + " must be an array of routing entries")
                with LOCK:
                    current = entries(which)
                    added, skipped = [], []
                    for entry in body.get("add", []):
                        entry = normalize_entry(entry)
                        (skipped if entry in current else added).append(entry)
                        if entry not in current:
                            current.append(entry)
                    to_remove = {normalize_entry(entry) for entry in body.get("remove", [])}
                    removed = [entry for entry in current if normalize_entry(entry) in to_remove]
                    current = [entry for entry in current if normalize_entry(entry) not in to_remove]
                    target = DATA_DIR / (which + ".list")
                    temporary = target.with_suffix(".tmp")
                    temporary.write_text("\n".join(current) + "\n", encoding="utf-8")
                    temporary.replace(target)
                return self.send({"list": which, "added": added, "skipped": skipped, "removed": removed})
            return self.send({"error": "Not found"}, 404)
        except (ValueError, TypeError, KeyError) as error:
            return self.send({"error": str(error)}, 400)


def main():
    # Never restore a session or authenticate on container startup/restart.
    port = load_config().get("docker", {}).get("api_port", 8889)
    def shutdown(*_):
        disconnect()
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    event("Docker daemon ready; waiting for an explicit Connect action")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
