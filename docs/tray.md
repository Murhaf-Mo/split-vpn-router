# Tray

Green requires both a connected VPN and active Windows routing. Up explicitly connects; Down stops routing and the managed container; Restart explicitly authenticates again. The mode toggle changes default routing, and Dashboard opens the authorized local UI.

Quit closes the tray without stopping routing. Tray autostart never starts authentication. Timeout leaves a manual-reconnect state rather than repeated MFA requests. Published release checks still run at most once per day.

Tray startup prepares the disconnected runtime. Startup/action failures appear in a visible error dialog and are saved under `runtime/tray.log` in the user data directory. Only an explicit Up/Connect action authenticates.
