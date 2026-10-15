# Configuration

Run `vpn configure` or copy [config.toml.example](../config.toml.example). Installed config lives under `%LOCALAPPDATA%\wsl-vpn-router`; checkout builds use the checkout.

| Setting | Default | Purpose |
| --- | --- | --- |
| `vpn.host`, `vpn.user`, `vpn.password` | required | Gateway and explicit-login credentials |
| `vpn.group` | empty | Optional authentication group |
| `vpn.dns_server` | empty | Corporate DNS override, otherwise VPN-provided DNS |
| `vpn.auto_reconnect` | `false` | Existing-cookie transport recovery only; never another password login |
| `docker.image` | `split-vpn-router:local` | Local image built from shipped sources |
| `docker.api_port` | `8889` | Loopback API/dashboard |
| `docker.relay_port` | `1080` | Encrypted TCP/UDP relay; not an HTTP proxy |
| `routing.mode` | `direct-default` | Default when neither list matches |
| `routing.direct_dns` | `1.1.1.1` | Home/public DNS IP; use LAN DNS if needed |
| `routing.manage_forwarding` | `false` | Opt in to pause outbound-adapter IP forwarding during routing and restore it afterward |

Ports must be distinct and between 1024 and 65535. No HTTP_PROXY or Git proxy is installed. Actual TOML parsers preserve quoted passwords and embedded `#` characters.

Old `[wsl]`/`[proxy]` tables are ignored and removed on canonical save; existing VPN credentials and mode are retained. Authentication changes apply at the next explicit connection. Port/image changes require an explicit restart. Lists/mode are watched and can reconnect sockets when policy is replaced.

Forwarding management takes effect on the next service start. Windows forwarding can defeat interface-bound sockets and create a routing loop. Up checks this before MFA. With management enabled, the service records only forwarding settings it changes, monitors outbound-adapter changes, and restores those settings on normal stop. An independent protected recovery process restores them after a service crash. Hotspot or machine-to-machine forwarding can pause while routing is active.
