# Architecture

```text
Windows application (TCP/UDP)
  -> Windows virtual adapter, managed by VPNRouter service
     -> direct outbound -> home network
     -> encrypted localhost relay -> Docker port mapping
        -> relay bound to tun0 -> OpenConnect -> corporate VPN

CLI / tray / dashboard -> authenticated localhost API -> Docker VPN daemon
```

Docker contains OpenConnect, its Linux tunnel/route hook, the TCP/UDP relay and the Python API/dashboard. It receives NET_ADMIN and the tunnel device in its own network namespace. It does not use privileged/host-network mode or modify another container, a WSL distro or Docker's resolv.conf.

The Windows service runs as LocalSystem and executes a pinned native sing-box binary. Its executables are copied into administrator-owned `%ProgramData%\VPNRouter\bin`, including for checkout builds; editing the checkout cannot replace a running privileged service. Docker commands run in the initiating user's context. The service neither runs Docker commands nor authenticates. Installation requires UAC; the initiating user receives start/stop/query access, not permission to replace the service executable.

The service starts manually through `vpn up`. It watches config, lists and Windows hosts mappings. Changes are validated before replacing the data plane; replacement can close sockets. FakeIP mappings persist across policy reloads. OS DNS caches are flushed on adapter start/stop; applications can retain their own caches.

Forwarding is checked before login. Optional `routing.manage_forwarding` records and pauses IP forwarding on outbound adapters before TUN startup, using protected recovery state and a separate watchdog process. It restores the original enabled settings after normal stop or a killed service. A captured routing-engine process is rejected before DNS/routing to bound recursion. Child console signaling runs in a separate helper so reload cannot signal the supervising service itself.

VPN rules precede direct rules. The VPN gateway and Docker transport bypass interception to prevent recursion. Corporate DNS goes through the relay. Windows hosts mappings produce IP rules because hosts lookups can bypass DNS. Shared-IP conflicts prefer VPN. URL inputs become host rules.

Connect starts one authentication subprocess. Its returned cookie stays in memory and goes to a separate noninteractive tunnel process without a password. Reconnect timeout defaults to zero, and the synchronous attempt-reconnect hook stops OpenConnect before even its initial transport retry unless reconnect was explicitly enabled. Container startup never authenticates or restores a session. Authentication timeout, declined MFA and session expiry never start another password login.

Relay egress and corporate DNS sockets bind to tun0. While the Windows service is active, VPN destinations fail if the relay is unavailable. Stopping/crashing the router removes interception; this is not a persistent firewall kill switch.

API/relay ports publish only to Windows loopback. The API requires a token and validates Host/Origin. `vpn dashboard` supplies the token in a fragment, then the page removes it and stores it per tab. Only a separate read-only health directory is mounted from the native service into Docker.

## Files

- Install: `C:\Program Files\wsl-vpn-router`.
- Per-user credentials/lists/VPN logs: `%LOCALAPPDATA%\wsl-vpn-router`.
- Protected native policy/cache/logs: `%ProgramData%\VPNRouter`.
- Read-only health: `%ProgramData%\VPNRouter\public\status.json`.

Registry/directory names remain compatible with previous releases. Checkout builds keep user data beside vpn.exe.
