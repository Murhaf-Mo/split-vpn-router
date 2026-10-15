# Dashboard

Run `vpn dashboard` to open the UI with its authorization token. Merely browsing to the port does not authorize API access.

The UI shows VPN/native router health, supports explicit Connect/Disconnect, edits lists and default mode, changes credentials/corporate DNS and exposes logs. Page load never connects. The reconnect checkbox defaults off and permits only existing-session transport recovery.

Initial service installation/start is managed by `vpn up`. If native routing is inactive, the UI asks you to run Up and does not report success just because the tunnel exists. Its container sees only a separate read-only health directory.

Opening `vpn dashboard` starts the passive container and idle Windows service if needed. Connect is available once native prerequisites pass, even while the adapter is inactive. A forwarding conflict appears on the page; enable forwarding management under VPN settings if acceptable, then save. Routing starts after the explicit login succeeds.
