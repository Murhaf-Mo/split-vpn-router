#!/usr/bin/env python3
"""OpenConnect route hook. Changes only this container's network namespace."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(os.environ.get("VPN_DATA_DIR", "/data")) / "runtime"


def ip(*args, check=True):
    return subprocess.run(["ip", *args], check=check, capture_output=True, text=True).stdout


def main():
    reason = os.environ.get("reason")
    device = os.environ.get("TUNDEV", "tun0")
    if reason == "attempt-reconnect":
        if os.environ.get("VPN_ALLOW_RECONNECT") != "1":
            # OpenConnect tries tcp_connect once even with reconnect-timeout=0.
            # The --script="exec ..." command makes OpenConnect our direct
            # parent, blocked in waitpid until this hook returns. Terminate it
            # before any reconnect I/O; the daemon restores container routes.
            parent = os.getppid()
            if Path(f"/proc/{parent}/comm").read_text().strip() != "openconnect":
                raise RuntimeError("Reconnect hook was not invoked by OpenConnect")
            os.kill(parent, 9)  # SIGKILL: cannot return to tcp_connect first.
    elif reason == "pre-init":
        routes = json.loads(ip("-j", "route", "show", "default"))
        if routes:
            (ROOT / "original-route.json").write_text(json.dumps(routes[0]))
        routes6 = json.loads(ip("-6", "-j", "route", "show", "default"))
        (ROOT / "original-route6.json").write_text(json.dumps(routes6[0] if routes6 else None))
    elif reason in ("connect", "reconnect"):
        original = json.loads((ROOT / "original-route.json").read_text())
        gateway = os.environ["VPNGATEWAY"]
        if ipaddress.ip_address(gateway).version == 4:
            ip("route", "replace", gateway + "/32", "via", original["gateway"], "dev", original["dev"])
        else:
            original6 = json.loads((ROOT / "original-route6.json").read_text())
            if original6:
                args = ["-6", "route", "replace", gateway + "/128"]
                if original6.get("gateway"):
                    args += ["via", original6["gateway"]]
                ip(*args, "dev", original6["dev"])
        ip("link", "set", device, "up", "mtu", os.environ.get("INTERNAL_IP4_MTU", "1300"))
        address = os.environ["INTERNAL_IP4_ADDRESS"]
        ip("addr", "replace", address + "/32", "dev", device)
        ip("route", "replace", "default", "dev", device)
        if os.environ.get("INTERNAL_IP6_ADDRESS"):
            address6 = os.environ["INTERNAL_IP6_ADDRESS"]
            if "/" not in address6:
                address6 += "/128"
            address6 = str(ipaddress.ip_interface(address6))
            ip("-6", "addr", "replace", address6, "dev", device)
            ip("-6", "route", "replace", "default", "dev", device)
        # Docker owns resolv.conf. Corporate DNS is consumed only by the VPN relay.
        dns = (os.environ.get("INTERNAL_IP4_DNS", "") + " " + os.environ.get("INTERNAL_IP6_DNS", "")).split()
        temporary = ROOT / "network.tmp"
        temporary.write_text(json.dumps({"address": address, "dns": dns, "gateway": gateway}))
        temporary.replace(ROOT / "network.json")
        for chain in ("OUTPUT", "FORWARD"):
            rule = [chain, "-o", device, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]
            exists = subprocess.run(["iptables", "-t", "mangle", "-C", *rule], capture_output=True).returncode == 0
            if not exists:
                subprocess.run(["iptables", "-t", "mangle", "-A", *rule], check=False)
    elif reason == "disconnect":
        if (ROOT / "original-route.json").exists():
            original = json.loads((ROOT / "original-route.json").read_text())
            ip("route", "replace", "default", "via", original["gateway"], "dev", original["dev"], check=False)
        if (ROOT / "original-route6.json").exists():
            original6 = json.loads((ROOT / "original-route6.json").read_text())
            if original6:
                args = ["-6", "route", "replace", "default"]
                if original6.get("gateway"):
                    args += ["via", original6["gateway"]]
                ip(*args, "dev", original6["dev"], check=False)
        (ROOT / "network.json").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
