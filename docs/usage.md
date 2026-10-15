# CLI usage

| Command | Behavior |
| --- | --- |
| `vpn up` | Explicit login and Windows routing; first use installs the service with UAC |
| `vpn down` | Stop routing/container, even with broken config |
| `vpn restart` | Disconnect and explicitly authenticate again |
| `vpn status` | VPN and native router health |
| `vpn mode [direct-default|vpn-default]` | Read/change default route |
| `vpn add [-vpn|-direct] <entry>...` | Add URLs/domains/IPs/CIDRs; works offline |
| `vpn remove [-vpn|-direct] <entry>...` | Remove rules; works offline |
| `vpn list`, `vpn reload`, `vpn sync-hosts` | Show lists/explain automatic watching |
| `vpn dashboard` | Open authorized local UI |
| `vpn logs [oc|pac|proxy] [-f]` | VPN, daemon or relay diagnostics |
| `vpn autostart [enable|disable|status]` | Tray startup only, never authentication |
| `vpn build-image` | Rebuild contained runtime |
| `vpn repair-proxy` | Back up/remove recognized legacy proxies |
| `vpn router-uninstall` | Remove service as administrator |
| `vpn upgrade`, `vpn version` | Published releases |

Connect operations are serialized. If the VPN is already connected but its Windows router stopped, Up restores routing without requesting another login. Policy changes can reconnect existing sockets.
