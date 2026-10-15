# Routing lists

`vpn.list` selects VPN destinations; `direct.list` selects home-network destinations. VPN rules precede direct rules, including overlapping CIDRs. Blank lines and `#` comments are accepted.

```text
internal.example.com
*.corp.example.com
10.77.0.0/16
2001:db8::/32
https://internal.example.com/some/page
```

Bare domains include subdomains. Wildcards use host glob matching. IPv4/IPv6 addresses and CIDRs are supported. A URL selects its entire host: the last example routes all of internal.example.com, since encrypted HTTPS paths cannot select packet routes.

Windows hosts-file mappings are watched automatically. If names sharing one IP conflict and the app supplies only that IP, VPN wins. Intercepted DNS/FakeIP and protocol sniffing preserve domain identities for ordinary applications. Encrypted DNS plus hidden hostnames or explicitly bound interfaces can require IP rules.

Invalid edits keep the working policy and surface a router error. Valid policy replacement may close existing sockets; retrying the application's request does not require another VPN login.
