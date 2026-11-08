// Package config loads runtime configuration from environment variables
// (populated from .env locally or a ConfigMap in Kubernetes).
package config

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"ca-chain-check/internal/theme"

	"gopkg.in/yaml.v3"
)

// DefaultDenyCIDRs are never testable by anyone: unspecified, link-local
// (includes cloud metadata 169.254.169.254), multicast, reserved, broadcast.
var DefaultDenyCIDRs = []string{
	"0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"255.255.255.255/32", "::/128", "ff00::/8", "fe80::/10", "fd00:ec2::254/128",
}

const DefaultMozillaRootsURL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"

// PendingDistrust marks a CA (by SHA-256 fingerprint) as scheduled to lose trust.
type PendingDistrust struct {
	Fingerprint string `yaml:"fingerprint" json:"fingerprint"` // lowercase hex, no separators
	Date        string `yaml:"date" json:"date,omitempty"`
	Note        string `yaml:"note" json:"note,omitempty"`
}

type Config struct {
	ListenAddr string

	RateLimitRPM   float64
	RateLimitBurst int
	MaxConcurrent  int
	TrustedProxies []netip.Prefix
	ClientIPHeader string // e.g. CF-Connecting-IP; honored only from trusted proxies

	TargetDenyCIDRs          []netip.Prefix
	PrivateTargetClientCIDRs []netip.Prefix
	PrivateTargetExtraCIDRs  []netip.Prefix
	AllowRequestIPOverride   bool
	IPOverrideClientCIDRs    []netip.Prefix
	DNSOverrides             map[string][]netip.Addr // key: lowercase host or "*.suffix"
	DNSServers               []string
	MaxIPsPerHost            int
	AllowedPorts             map[int]bool // empty = all
	DisableIPv6              bool         // test IPv4 addresses only

	DialTimeout      time.Duration
	HandshakeTimeout time.Duration

	CheckRevocation   bool          // ask OCSP responders and CRLs about the best path
	RevocationTimeout time.Duration // per OCSP or CRL fetch

	MozillaRootsURL   string
	TruststoreRefresh time.Duration
	ExpiringSoonDays  int

	PendingDistrust map[string]PendingDistrust // key: fingerprint

	Theme []theme.Entry // local colour overrides (THEME_COLORS)
}

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.Getenv) }

// LoadFrom reads configuration using the supplied lookup (for tests).
func LoadFrom(get func(string) string) (*Config, error) {
	c := &Config{}
	var err error
	str := func(k, def string) string {
		if v := strings.TrimSpace(get(k)); v != "" {
			return v
		}
		return def
	}
	fail := func(k string, e error) error { return fmt.Errorf("config %s: %w", k, e) }

	c.ListenAddr = str("LISTEN_ADDR", ":8080")
	c.ClientIPHeader = str("CLIENT_IP_HEADER", "")
	if c.RateLimitRPM, err = strconv.ParseFloat(str("RATE_LIMIT_RPM", "10"), 64); err != nil || c.RateLimitRPM <= 0 {
		return nil, fail("RATE_LIMIT_RPM", fmt.Errorf("must be a positive number"))
	}
	ints := []struct {
		key string
		def string
		dst *int
	}{
		{"RATE_LIMIT_BURST", "5", &c.RateLimitBurst},
		{"MAX_CONCURRENT_PROBES", "20", &c.MaxConcurrent},
		{"MAX_IPS_PER_HOST", "16", &c.MaxIPsPerHost},
		{"EXPIRING_SOON_DAYS", "30", &c.ExpiringSoonDays},
	}
	for _, i := range ints {
		if *i.dst, err = strconv.Atoi(str(i.key, i.def)); err != nil || *i.dst < 1 {
			return nil, fail(i.key, fmt.Errorf("must be a positive integer"))
		}
	}
	durs := []struct {
		key string
		def string
		dst *time.Duration
	}{
		{"DIAL_TIMEOUT", "5s", &c.DialTimeout},
		{"HANDSHAKE_TIMEOUT", "5s", &c.HandshakeTimeout},
		{"REVOCATION_TIMEOUT", "5s", &c.RevocationTimeout},
		{"TRUSTSTORE_REFRESH", "24h", &c.TruststoreRefresh},
	}
	for _, d := range durs {
		if *d.dst, err = time.ParseDuration(str(d.key, d.def)); err != nil || *d.dst <= 0 {
			return nil, fail(d.key, fmt.Errorf("must be a positive duration"))
		}
	}

	cidrs := []struct {
		key string
		def string
		dst *[]netip.Prefix
	}{
		{"TRUSTED_PROXIES", "", &c.TrustedProxies},
		{"TARGET_DENY_CIDRS", strings.Join(DefaultDenyCIDRs, ","), &c.TargetDenyCIDRs},
		{"PRIVATE_TARGET_CLIENT_CIDRS", "", &c.PrivateTargetClientCIDRs},
		{"PRIVATE_TARGET_EXTRA_CIDRS", "", &c.PrivateTargetExtraCIDRs},
		{"IP_OVERRIDE_CLIENT_CIDRS", "", &c.IPOverrideClientCIDRs},
	}
	for _, p := range cidrs {
		if *p.dst, err = ParseCIDRList(str(p.key, p.def)); err != nil {
			return nil, fail(p.key, err)
		}
	}

	if c.CheckRevocation, err = strconv.ParseBool(str("CHECK_REVOCATION", "true")); err != nil {
		return nil, fail("CHECK_REVOCATION", err)
	}
	if c.DisableIPv6, err = strconv.ParseBool(str("DISABLE_IPV6", "false")); err != nil {
		return nil, fail("DISABLE_IPV6", err)
	}
	if c.AllowRequestIPOverride, err = strconv.ParseBool(str("ALLOW_REQUEST_IP_OVERRIDE", "true")); err != nil {
		return nil, fail("ALLOW_REQUEST_IP_OVERRIDE", err)
	}
	if c.DNSOverrides, err = ParseDNSOverrides(get("DNS_OVERRIDES")); err != nil {
		return nil, fail("DNS_OVERRIDES", err)
	}
	for _, s := range splitList(get("DNS_SERVERS")) {
		if _, _, e := splitHostPortDefault(s, "53"); e != nil {
			return nil, fail("DNS_SERVERS", e)
		}
		h, p, _ := splitHostPortDefault(s, "53")
		c.DNSServers = append(c.DNSServers, joinHostPort(h, p))
	}
	c.AllowedPorts = map[int]bool{}
	for _, s := range splitList(get("ALLOWED_PORTS")) {
		p, e := strconv.Atoi(s)
		if e != nil || p < 1 || p > 65535 {
			return nil, fail("ALLOWED_PORTS", fmt.Errorf("invalid port %q", s))
		}
		c.AllowedPorts[p] = true
	}

	if c.Theme, err = theme.Parse(get("THEME_COLORS")); err != nil {
		return nil, err
	}

	c.MozillaRootsURL = str("MOZILLA_ROOTS_URL", DefaultMozillaRootsURL)

	c.PendingDistrust = map[string]PendingDistrust{}
	for _, pd := range ParsePendingDistrustEnv(get("PENDING_DISTRUST")) {
		c.PendingDistrust[pd.Fingerprint] = pd
	}
	if f := strings.TrimSpace(get("PENDING_DISTRUST_FILE")); f != "" {
		data, e := os.ReadFile(f)
		if e != nil {
			slog.Warn("cannot read PENDING_DISTRUST_FILE", "file", f, "err", e)
		} else {
			for _, pd := range ParsePendingDistrustYAML(data) {
				c.PendingDistrust[pd.Fingerprint] = pd
			}
		}
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ParseCIDRList parses comma/space separated CIDRs; bare IPs become /32 or /128.
func ParseCIDRList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range splitList(s) {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or IP %q", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// ParseDNSOverrides parses "host=ip,ip;*.suffix=ip".
func ParseDNSOverrides(s string) (map[string][]netip.Addr, error) {
	out := map[string][]netip.Addr{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, ips, ok := strings.Cut(entry, "=")
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if !ok || host == "" {
			return nil, fmt.Errorf("entry %q must be host=ip[,ip]", entry)
		}
		for _, ipStr := range splitList(ips) {
			a, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("entry %q: invalid IP %q", entry, ipStr)
			}
			out[host] = append(out[host], a.Unmap())
		}
		if len(out[host]) == 0 {
			return nil, fmt.Errorf("entry %q has no IPs", entry)
		}
	}
	return out, nil
}

// NormalizeFingerprint strips separators and lowercases; returns "" if not a SHA-256 hex.
func NormalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "sha256/")
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

// ParsePendingDistrustEnv parses "FP[|DATE[|NOTE]];..." entries. The separator
// between fields is "|" because fingerprints may themselves contain colons;
// for convenience a colon-free fingerprint may also use ":" as the separator.
func ParsePendingDistrustEnv(s string) []PendingDistrust {
	var out []PendingDistrust
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		var parts []string
		if strings.Contains(entry, "|") {
			parts = strings.SplitN(entry, "|", 3)
		} else {
			parts = strings.SplitN(entry, ":", 3)
			// Colon-separated hex fingerprint with no metadata.
			if NormalizeFingerprint(parts[0]) == "" && NormalizeFingerprint(entry) != "" {
				parts = []string{entry}
			}
		}
		pd := PendingDistrust{Fingerprint: NormalizeFingerprint(parts[0])}
		if pd.Fingerprint == "" {
			slog.Warn("ignoring malformed PENDING_DISTRUST entry", "entry", entry)
			continue
		}
		if len(parts) > 1 {
			pd.Date = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			pd.Note = strings.TrimSpace(parts[2])
		}
		out = append(out, pd)
	}
	return out
}

// ParsePendingDistrustYAML parses a YAML list of {fingerprint, date, note}.
func ParsePendingDistrustYAML(data []byte) []PendingDistrust {
	var raw []PendingDistrust
	if err := yaml.Unmarshal(data, &raw); err != nil {
		slog.Warn("cannot parse pending distrust YAML", "err", err)
		return nil
	}
	var out []PendingDistrust
	for _, pd := range raw {
		fp := NormalizeFingerprint(pd.Fingerprint)
		if fp == "" {
			slog.Warn("ignoring malformed pending distrust fingerprint", "fingerprint", pd.Fingerprint)
			continue
		}
		pd.Fingerprint = fp
		out = append(out, pd)
	}
	return out
}
