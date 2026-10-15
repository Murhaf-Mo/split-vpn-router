// Package router generates domain/IP policy for the Windows TUN data plane.
package router

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

type Rule map[string]any
type Policy struct {
	Mode, Key, DirectDNS, CorpDNS, Gateway, VPNHost string
	RouterProcessPath                               string
	RelayPort                                       int
	VPN, Direct                                     []string
	Hosts                                           string
}

func Normalize(entry string) (string, error) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if strings.Contains(entry, "://") {
		u, err := url.Parse(entry)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return "", fmt.Errorf("invalid URL %q", entry)
		}
		entry = u.Hostname()
	}
	if p, err := netip.ParsePrefix(entry); err == nil {
		return p.Masked().String(), nil
	}
	if ip, err := netip.ParseAddr(entry); err == nil {
		return netip.PrefixFrom(ip, ip.BitLen()).String(), nil
	}
	if entry == "" || strings.ContainsAny(entry, "/\\\n\r\t #:@") {
		return "", fmt.Errorf("invalid routing entry %q; use a full HTTP(S) URL, domain or IP/CIDR", entry)
	}
	return entry, nil
}

func ParseList(text string) []string {
	var result []string
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func Matcher(entry string) (Rule, error) {
	s, err := Normalize(entry)
	if err != nil {
		return nil, err
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return Rule{"ip_cidr": []string{p.String()}}, nil
	}
	if strings.ContainsAny(s, "*?") {
		pattern := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(s), `\*`, ".*"), `\?`, ".") + "$"
		return Rule{"domain_regex": []string{pattern}}, nil
	}
	return Rule{"domain_suffix": []string{s}}, nil
}

func matchesHost(entry, host string) bool {
	m, err := Matcher(entry)
	if err != nil {
		return false
	}
	if suffix, ok := m["domain_suffix"].([]string); ok {
		return host == suffix[0] || strings.HasSuffix(host, "."+suffix[0])
	}
	if patterns, ok := m["domain_regex"].([]string); ok {
		return regexp.MustCompile(patterns[0]).MatchString(host)
	}
	return false
}

// HostsRules covers connections whose Windows hosts-file lookup bypasses DNS.
// Two names on the same IP cannot receive different packet routes; VPN wins.
func HostsRules(hosts string, vpn, direct []string) (v, d []Rule) {
	seen := map[string]string{}
	for _, line := range strings.Split(hosts, "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || ip.IsLoopback() {
			continue
		}
		for _, host := range fields[1:] {
			for _, entry := range direct {
				if matchesHost(entry, strings.ToLower(host)) && seen[ip.String()] != "vpn" {
					seen[ip.String()] = "direct"
				}
			}
			for _, entry := range vpn {
				if matchesHost(entry, strings.ToLower(host)) {
					seen[ip.String()] = "vpn"
				}
			}
		}
	}
	for address, target := range seen {
		r, _ := Matcher(address)
		r["action"] = "route"
		r["outbound"] = target
		if target == "vpn" {
			v = append(v, r)
		} else {
			d = append(d, r)
		}
	}
	return
}

func Generate(p Policy) ([]byte, error) {
	if p.Mode != "direct-default" && p.Mode != "vpn-default" {
		return nil, fmt.Errorf("invalid routing mode")
	}
	if _, err := netip.ParseAddr(p.DirectDNS); err != nil {
		return nil, fmt.Errorf("routing.direct_dns must be an IP address")
	}
	if _, err := netip.ParseAddr(p.CorpDNS); err != nil {
		return nil, fmt.Errorf("corporate DNS is unavailable")
	}
	final, dnsFinal := "direct", "home-dns"
	if p.Mode == "vpn-default" {
		final = "vpn"
		dnsFinal = "corp-dns"
	}
	rules := []Rule{
		{"port": []int{53}, "action": "hijack-dns"},
		{"ip_cidr": []string{"172.31.255.2/32", "fdfe:dcba:9876::2/128"}, "action": "reject"},
		{"action": "sniff", "timeout": "300ms"},
		{"protocol": "dns", "action": "hijack-dns"},
		// Prevent Docker's VPN transport from entering its own tunnel.
		{"process_name": []string{"com.docker.backend.exe", "Docker Desktop.exe", "docker.exe", "vpn.exe", "vpn-tray.exe"}, "action": "route", "outbound": "direct"},
		{"ip_cidr": []string{"127.0.0.0/8", "::1/128"}, "action": "route", "outbound": "direct"},
	}
	if p.RouterProcessPath != "" {
		// Never turn one bad Windows egress route into an unbounded packet loop.
		rules = append([]Rule{{"process_path": []string{p.RouterProcessPath}, "action": "reject"}}, rules...)
	}
	dnsRules := []Rule{}
	// VPN authentication/transport must remain outside its own data tunnel,
	// including fresh manual connections after a timed-out session.
	if p.VPNHost != "" {
		hostURL := p.VPNHost
		if !strings.Contains(hostURL, "://") {
			hostURL = "https://" + hostURL
		}
		parsed, err := url.Parse(hostURL)
		if err != nil || parsed.Hostname() == "" {
			return nil, fmt.Errorf("invalid VPN host")
		}
		host := parsed.Hostname()
		rules = append(rules, Rule{"domain": []string{host}, "action": "route", "outbound": "direct"})
		dnsRules = append(dnsRules, Rule{"domain": []string{host}, "action": "route", "server": "home-dns"})
	}
	dnsRules = append(dnsRules, Rule{"process_name": []string{"com.docker.backend.exe", "Docker Desktop.exe", "docker.exe"}, "action": "route", "server": "home-dns"})
	var vpnIP, directIP, directDomains, directResolves []Rule
	for _, list := range []struct {
		entries     []string
		target, dns string
	}{{p.VPN, "vpn", "corp-dns"}, {p.Direct, "direct", "home-dns"}} {
		for _, entry := range list.entries {
			matcher, err := Matcher(entry)
			if err != nil {
				return nil, err
			}
			dnsRule := Rule{}
			for k, v := range matcher {
				dnsRule[k] = v
			}
			matcher["action"] = "route"
			matcher["outbound"] = list.target
			if _, ip := matcher["ip_cidr"]; ip {
				if list.target == "vpn" {
					vpnIP = append(vpnIP, matcher)
				} else {
					directIP = append(directIP, matcher)
				}
			} else {
				if list.target == "vpn" {
					rules = append(rules, matcher)
				} else {
					directDomains = append(directDomains, matcher)
					resolve := Rule{}
					for k, v := range dnsRule {
						resolve[k] = v
					}
					resolve["action"] = "resolve"
					resolve["server"] = "home-dns"
					directResolves = append(directResolves, resolve)
				}
				dnsRule["action"] = "route"
				dnsRule["server"] = list.dns
				dnsRules = append(dnsRules, dnsRule)
			}
		}
	}
	hostVPN, hostDirect := HostsRules(p.Hosts, p.VPN, p.Direct)
	rules = append(rules, hostVPN...)
	// Resolve direct names through home DNS before testing VPN CIDRs. All VPN
	// rules must beat direct rules, including names mapped in the hosts file.
	rules = append(rules, directResolves...)
	defaultResolve := Rule{"action": "resolve", "server": dnsFinal}
	if len(directResolves) > 0 {
		var directMatchers []Rule
		for _, resolve := range directResolves {
			matcher := Rule{}
			for key, value := range resolve {
				if key != "action" && key != "server" {
					matcher[key] = value
				}
			}
			directMatchers = append(directMatchers, matcher)
		}
		defaultResolve["type"] = "logical"
		defaultResolve["mode"] = "or"
		defaultResolve["rules"] = directMatchers
		defaultResolve["invert"] = true
	}
	rules = append(rules, defaultResolve)
	rules = append(rules, vpnIP...)
	rules = append(rules, directDomains...)
	rules = append(rules, hostDirect...)
	rules = append(rules, directIP...)
	// Fake IPs preserve the domain even for encrypted TLS/QUIC and shared CDNs.
	// Infrastructure uses real addresses; application A/AAAA lookups use FakeIP.
	boundary := 1
	if p.VPNHost != "" {
		boundary = 2
	}
	dnsRules = append(dnsRules[:boundary], append([]Rule{{"query_type": []string{"A", "AAAA"}, "action": "route", "server": "fake"}}, dnsRules[boundary:]...)...)
	tun := Rule{"type": "tun", "tag": "windows", "interface_name": "VPN Router",
		"address": []string{"172.31.255.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1300,
		"dns_address": []string{"172.31.255.2", "fdfe:dcba:9876::2"},
		"auto_route":  true, "strict_route": true, "stack": "mixed"}
	if gateway, err := netip.ParseAddr(p.Gateway); err == nil {
		tun["route_exclude_address"] = []string{netip.PrefixFrom(gateway, gateway.BitLen()).String()}
	}
	config := map[string]any{
		"log":      Rule{"level": "warn", "timestamp": true},
		"inbounds": []Rule{tun},
		"outbounds": []Rule{
			{"type": "direct", "tag": "direct", "domain_resolver": "home-dns"},
			{"type": "shadowsocks", "tag": "vpn", "server": "127.0.0.1", "server_port": p.RelayPort,
				"method": "chacha20-ietf-poly1305", "password": p.Key},
		},
		"dns": Rule{"servers": []Rule{
			{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
			{"type": "udp", "tag": "home-dns", "server": p.DirectDNS, "detour": "direct"},
			{"type": "tcp", "tag": "corp-dns", "server": p.CorpDNS, "detour": "vpn"},
		}, "rules": dnsRules, "final": dnsFinal, "reverse_mapping": true},
		"route":        Rule{"rules": rules, "final": final, "auto_detect_interface": true, "default_domain_resolver": dnsFinal},
		"experimental": Rule{"cache_file": Rule{"enabled": true, "path": "fakeip.db", "store_fakeip": true}},
	}
	return json.MarshalIndent(config, "", "  ")
}
