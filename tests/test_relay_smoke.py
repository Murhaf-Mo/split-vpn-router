"""Optional real-engine TCP/UDP test. Opens localhost sockets; never creates a TUN."""
import contextlib
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ENGINE = os.environ.get("SING_BOX_BIN")


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def exact(stream, size):
    data = b""
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise IOError("Socket closed")
        data += part
    return data


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(8192))


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, stream = self.request
        stream.sendto(data, self.client_address)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, stream = self.request
        self.server.queries += 1
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 5  # root label, query type, class
        if self.server.refuse:
            response = data[:2] + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:end]
        else:
            response = (data[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + data[12:end]
                        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\x7f\x00\x00\x01")
        stream.sendto(response, self.client_address)


@unittest.skipUnless(ENGINE, "Set SING_BOX_BIN for real-engine local relay verification")
class RelaySmokeTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("VPN_ROUTER_CONFIG_FIXTURE"), "Set VPN_ROUTER_CONFIG_FIXTURE for generated-policy checks")
    def test_generated_policy_resolves_direct_domains_and_vpn_cidrs_win(self):
        for cidr_wins in (False, True):
            with self.subTest(cidr_wins=cidr_wins), tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
                echo = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCPHandler))
                home = stack.enter_context(socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler))
                corp = stack.enter_context(socketserver.ThreadingUDPServer(("127.0.0.1", 0), DNSHandler))
                home.refuse, corp.refuse = False, True
                home.queries = corp.queries = 0
                for server in (echo, home, corp):
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    stack.callback(server.shutdown)
                config = json.loads(Path(os.environ["VPN_ROUTER_CONFIG_FIXTURE"]).read_text())
                config["log"]["level"] = "error"
                socks_port = port()
                config["inbounds"] = [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}]
                config["route"]["auto_detect_interface"] = False
                config["route"]["final"] = "vpn"
                config["experimental"]["cache_file"]["path"] = str(Path(directory) / "cache.db")
                config["outbounds"][1]["server_port"] = port()  # deliberately unavailable VPN relay
                for rule in config["route"]["rules"]:
                    if rule.get("action") == "resolve" and "domain_regex" not in rule:
                        rule["server"] = "corp-dns"
                    if cidr_wins and rule.get("outbound") == "vpn" and "ip_cidr" in rule:
                        rule["ip_cidr"] = ["127.0.0.0/8"]
                for resolver in config["dns"]["servers"]:
                    if resolver["tag"] in ("home-dns", "corp-dns"):
                        resolver.update(type="udp", server="127.0.0.1", server_port=home.server_address[1] if resolver["tag"] == "home-dns" else corp.server_address[1])
                        resolver.pop("detour", None)
                path = Path(directory) / "router.json"
                path.write_text(json.dumps(config))
                log = stack.enter_context((Path(directory) / "router.log").open("w"))
                proc = subprocess.Popen([ENGINE, "run", "-c", str(path)], stdout=log, stderr=log,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                def terminate():
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=5)
                stack.callback(terminate)
                for _ in range(50):
                    try:
                        with socket.create_connection(("127.0.0.1", socks_port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as stream:
                    stream.sendall(b"\x05\x01\x00")
                    self.assertEqual(exact(stream, 2), b"\x05\x00")
                    name = b"public.example.com"
                    stream.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", echo.server_address[1]))
                    response = exact(stream, 4)
                    if cidr_wins:
                        if response[1] == 0:
                            exact(stream, 6)
                            stream.sendall(b"blocked")
                            self.assertEqual(stream.recv(20), b"", "VPN CIDR must beat direct domain; unavailable relay must fail")
                    else:
                        self.assertEqual(response[1], 0, "Direct domain must resolve through home DNS and bypass an unavailable VPN")
                        exact(stream, 6)
                        stream.sendall(b"direct traffic works")
                        self.assertEqual(exact(stream, 20), b"direct traffic works")
                        self.assertEqual(corp.queries, 0, "A resolved direct name must not be looked up through unavailable corporate DNS")

    def test_tcp_and_udp_cross_encrypted_relay(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            tcp = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCPHandler))
            udp = stack.enter_context(socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDPHandler))
            for server in (tcp, udp):
                threading.Thread(target=server.serve_forever, daemon=True).start()
                stack.callback(server.shutdown)
            relay_port, socks_port = port(), port()
            server_config = {"inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": relay_port,
                                           "method": "chacha20-ietf-poly1305", "password": "local-smoke-key"}],
                             "outbounds": [{"type": "direct", "tag": "exit"}], "route": {"final": "exit"}}
            client_config = {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                             "outbounds": [{"type": "shadowsocks", "tag": "relay", "server": "127.0.0.1", "server_port": relay_port,
                                            "method": "chacha20-ietf-poly1305", "password": "local-smoke-key"}],
                             "route": {"final": "relay"}}
            for name, config in (("server", server_config), ("client", client_config)):
                path = Path(directory) / (name + ".json")
                path.write_text(json.dumps(config))
                log = stack.enter_context((Path(directory) / (name + ".log")).open("w"))
                proc = subprocess.Popen([ENGINE, "run", "-c", str(path)], stdout=log, stderr=log,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                def terminate(proc=proc):
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=5)
                stack.callback(terminate)
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            address = socket.inet_aton("127.0.0.1")
            payload = b"VPN router TCP/UDP round trip"
            with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as stream:
                stream.sendall(b"\x05\x01\x00")
                self.assertEqual(exact(stream, 2), b"\x05\x00")
                stream.sendall(b"\x05\x01\x00\x01" + address + struct.pack("!H", tcp.server_address[1]))
                self.assertEqual(exact(stream, 4)[:2], b"\x05\x00")
                exact(stream, 6)
                stream.sendall(payload)
                self.assertEqual(exact(stream, len(payload)), payload)
            with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                stream.sendall(b"\x05\x01\x00")
                self.assertEqual(exact(stream, 2), b"\x05\x00")
                stream.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
                header = exact(stream, 4)
                self.assertEqual(header[:2], b"\x05\x00")
                self.assertEqual(header[3], 1)
                relay_address = socket.inet_ntoa(exact(stream, 4))
                relay_udp_port = struct.unpack("!H", exact(stream, 2))[0]
                datagram.settimeout(5)
                packet = b"\x00\x00\x00\x01" + address + struct.pack("!H", udp.server_address[1]) + payload
                datagram.sendto(packet, ("127.0.0.1" if relay_address == "0.0.0.0" else relay_address, relay_udp_port))
                reply, _ = datagram.recvfrom(8192)
                self.assertEqual(reply[10:], payload)
