# Quickstart

Start Docker Desktop with Linux containers, then:

```powershell
vpn configure
vpn up
vpn add https://internal.example.com
vpn add -direct github.com
vpn status
vpn dashboard
```

First Up prepares the Windows service with UAC. Approve the explicitly initiated MFA request. Default routing is direct except listed VPN destinations. HTTP and SSH traffic use native routes without per-app proxy setup.

`vpn down` stops native routing and removes the managed container, even with broken configuration. Tray autostart only opens the tray. After a timeout choose Up/Connect when ready; no password login is retried automatically.
