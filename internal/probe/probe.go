// Package probe resolves a target, applies the target policy to every IP,
// performs TLS handshakes (SNI, no trust verification) and analyzes each chain.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"ca-chain-check/internal/analyze"
	"ca-chain-check/internal/config"
	"ca-chain-check/internal/netguard"
	"ca-chain-check/internal/truststore"
)

// Resolution sources.
const (
	SourceDNS             = "dns"
	SourceConfigOverride  = "config_override"
	SourceRequestOverride = "request_override"
	SourceLiteral         = "ip_literal"
)

// Request is the API input.
type Request struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	ConnectIPs []string `json:"connectIPs,omitempty"`
}

// TLSInfo describes the negotiated session.
type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipherSuite"`
	ALPN        string `json:"alpn,omitempty"`
	SNI         string `json:"sni,omitempty"`
	HandshakeMS int64  `json:"handshakeMs"`
}

// IPResult is the outcome for one target IP.
type IPResult struct {
	IP         string          `json:"ip"`
	Tested     bool            `json:"tested"`
	DenyReason string          `json:"denyReason,omitempty"`
	Error      string          `json:"error,omitempty"`
	TLS        *TLSInfo        `json:"tls,omitempty"`
	Analysis   *analyze.Result `json:"analysis,omitempty"`
	Overall    string          `json:"overall"`
	chainKey   string
}

// Resolution reports how IPs were obtained.
type Resolution struct {
	Source  string   `json:"source"`
	IPs     []string `json:"ips"`
	Skipped []string `json:"skipped,omitempty"` // beyond MAX_IPS_PER_HOST
	// IPv4Only is set when DISABLE_IPV6 is on; Dropped lists IPv6 addresses
	// that were resolved but not tested.
	IPv4Only bool     `json:"ipv4Only,omitempty"`
	Dropped  []string `json:"droppedIPv6,omitempty"`
}

// Consistency compares chains across IPs.
type Consistency struct {
	Status string     `json:"status"` // pass | warn | info
	Detail string     `json:"detail"`
	Groups [][]string `json:"groups,omitempty"` // IPs serving identical chains
}

// Response is the API output.
type Response struct {
	Host        string          `json:"host"`
	Port        int             `json:"port"`
	CheckedAt   time.Time       `json:"checkedAt"`
	Resolution  Resolution      `json:"resolution"`
	Results     []IPResult      `json:"results"`
	Consistency Consistency     `json:"consistency"`
	TrustStore  truststore.Info `json:"trustStore"`
}

// InputError is a client error (400).
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErr(f string, a ...any) error { return &InputError{Msg: fmt.Sprintf(f, a...)} }

// Prober holds dependencies.
type Prober struct {
	Cfg      *config.Config
	Guard    *netguard.Guard
	Store    *truststore.Store
	Sem      chan struct{} // global concurrency cap on handshakes
	Resolver *net.Resolver
	// Dial is overridable for tests; it must connect to exactly addr.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewResolver builds a resolver that uses the given servers (round-robin
// fallback), or the system resolver when none are given.
func NewResolver(servers []string, timeout time.Duration) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			var last error
			for _, s := range servers {
				c, err := d.DialContext(ctx, network, s)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

// NormalizeHost validates and IDNA-encodes a hostname or IP literal.
func NormalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" {
		return "", inputErr("hostname is required")
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(h))
	if err != nil || len(ascii) > 253 {
		return "", inputErr("invalid hostname %q", h)
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", inputErr("invalid hostname %q", h)
		}
		for _, r := range label {
			if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return "", inputErr("invalid hostname %q", h)
			}
		}
	}
	return ascii, nil
}

// lookupOverride finds exact or wildcard ("*.suffix") overrides; longest suffix wins.
func lookupOverride(m map[string][]netip.Addr, host string) []netip.Addr {
	if ips, ok := m[host]; ok {
		return ips
	}
	var best string
	for k := range m {
		if strings.HasPrefix(k, "*.") {
			suf := k[1:] // ".suffix"
			if strings.HasSuffix(host, suf) && len(suf) > len(best) {
				best = k
			}
		}
	}
	if best != "" {
		return m[best]
	}
	return nil
}

func (p *Prober) resolve(ctx context.Context, client netip.Addr, host string, connectIPs []string) ([]netip.Addr, string, error) {
	if len(connectIPs) > 0 {
		if err := p.Guard.CheckOverride(client); err != nil {
			return nil, "", &InputError{Msg: err.Error()}
		}
		var out []netip.Addr
		for _, s := range connectIPs {
			s = strings.Trim(strings.TrimSpace(s), "[]")
			if s == "" {
				continue
			}
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, "", inputErr("invalid connect IP %q", s)
			}
			a = a.Unmap()
			if p.Cfg.DisableIPv6 && a.Is6() {
				return nil, "", inputErr("IPv6 is disabled on this server; %s cannot be tested", a)
			}
			out = append(out, a)
		}
		if len(out) > 0 {
			return out, SourceRequestOverride, nil
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if p.Cfg.DisableIPv6 && a.Unmap().Is6() {
			return nil, "", inputErr("IPv6 is disabled on this server; %s cannot be tested", host)
		}
		return []netip.Addr{a}, SourceLiteral, nil
	}
	if ips := lookupOverride(p.Cfg.DNSOverrides, host); len(ips) > 0 {
		return ips, SourceConfigOverride, nil
	}
	rctx, cancel := context.WithTimeout(ctx, p.Cfg.DialTimeout)
	defer cancel()
	network := "ip"
	if p.Cfg.DisableIPv6 {
		network = "ip4" // don't even ask for AAAA records
	}
	addrs, err := p.Resolver.LookupNetIP(rctx, network, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if p.Cfg.DisableIPv6 {
				return nil, "", inputErr("hostname %q has no IPv4 address (IPv6 is disabled on this server)", host)
			}
			return nil, "", inputErr("hostname %q does not resolve", host)
		}
		return nil, "", fmt.Errorf("DNS lookup failed: %w", err)
	}
	out := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap()
	}
	return out, SourceDNS, nil
}

func dedupeSort(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { // IPv4 first, then natural order
		if out[i].Is4() != out[j].Is4() {
			return out[i].Is4()
		}
		return out[i].Less(out[j])
	})
	return out
}

// Plan resolves the request and returns the IPs to probe (for rate-limit
// costing) without dialing anything.
func (p *Prober) Plan(ctx context.Context, client netip.Addr, req *Request) (host string, ips []netip.Addr, res Resolution, err error) {
	host, err = NormalizeHost(req.Host)
	if err != nil {
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Port < 1 || req.Port > 65535 {
		err = inputErr("port must be between 1 and 65535")
		return
	}
	if len(p.Cfg.AllowedPorts) > 0 && !p.Cfg.AllowedPorts[req.Port] {
		err = inputErr("port %d is not allowed on this server", req.Port)
		return
	}
	if len(req.ConnectIPs) > p.Cfg.MaxIPsPerHost {
		err = inputErr("enter at most %d connect IPs", p.Cfg.MaxIPsPerHost)
		return
	}
	all, source, err := p.resolve(ctx, client, host, req.ConnectIPs)
	if err != nil {
		return
	}
	all = dedupeSort(all)
	res.Source = source
	if p.Cfg.DisableIPv6 {
		res.IPv4Only = true
		v4 := all[:0:0]
		for _, a := range all {
			if a.Is6() {
				res.Dropped = append(res.Dropped, a.String())
			} else {
				v4 = append(v4, a)
			}
		}
		if len(v4) == 0 {
			err = inputErr("%s has only IPv6 addresses, and IPv6 is disabled on this server", host)
			return
		}
		all = v4
	}
	for i, a := range all {
		if i < p.Cfg.MaxIPsPerHost {
			ips = append(ips, a)
			res.IPs = append(res.IPs, a.String())
		} else {
			res.Skipped = append(res.Skipped, a.String())
		}
	}
	return
}

// Run probes every planned IP concurrently and analyzes the results.
func (p *Prober) Run(ctx context.Context, client netip.Addr, host string, port int, ips []netip.Addr, res Resolution) *Response {
	resp := &Response{Host: host, Port: port, CheckedAt: time.Now().UTC(), Resolution: res, TrustStore: p.Store.Info()}
	resp.Results = make([]IPResult, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		resp.Results[i].IP = ip.String()
		if err := p.Guard.CheckTarget(client, ip); err != nil {
			resp.Results[i].DenyReason = err.Error()
			resp.Results[i].Overall = analyze.Info
			continue
		}
		wg.Add(1)
		go func(r *IPResult, ip netip.Addr) {
			defer wg.Done()
			p.probeOne(ctx, r, host, port, ip)
		}(&resp.Results[i], ip)
	}
	wg.Wait()
	resp.Consistency = consistency(resp.Results)
	return resp
}

func (p *Prober) probeOne(ctx context.Context, r *IPResult, host string, port int, ip netip.Addr) {
	select {
	case p.Sem <- struct{}{}:
		defer func() { <-p.Sem }()
	case <-ctx.Done():
		r.Error = "server busy: " + ctx.Err().Error()
		r.Overall = analyze.Fail
		return
	}
	r.Tested = true
	certs, info, err := p.handshake(ctx, host, port, ip)
	if err != nil {
		r.Error = err.Error()
		r.Overall = analyze.Fail
		return
	}
	r.TLS = info
	r.Analysis = analyze.Analyze(certs, analyze.Options{
		Host:         host, // VerifyHostname also handles IP-literal SANs
		Now:          time.Now(),
		ExpiringSoon: time.Duration(p.Cfg.ExpiringSoonDays) * 24 * time.Hour,
		Store:        p.Store,
		Pending:      p.Cfg.PendingDistrust,
	})
	r.Overall = r.Analysis.Overall
	var fps []string
	for _, c := range r.Analysis.Chain {
		fps = append(fps, c.SHA256)
	}
	r.chainKey = strings.Join(fps, ",")
}

func (p *Prober) handshake(ctx context.Context, host string, port int, ip netip.Addr) ([]*x509.Certificate, *TLSInfo, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, p.Cfg.DialTimeout)
	defer cancel()
	dial := p.Dial
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	raw, err := dial(dctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s failed: %s", addr, cleanErr(err))
	}
	defer raw.Close()

	sni := host
	if _, err := netip.ParseAddr(host); err == nil {
		sni = "" // SNI must not carry IP literals
	}
	conf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // intentional: we analyze trust ourselves
		MinVersion:         tls.VersionTLS10,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	conn := tls.Client(raw, conf)
	hctx, hcancel := context.WithTimeout(ctx, p.Cfg.HandshakeTimeout)
	defer hcancel()
	start := time.Now()
	if err := conn.HandshakeContext(hctx); err != nil {
		return nil, nil, fmt.Errorf("TLS handshake with %s failed: %s", addr, cleanErr(err))
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	return st.PeerCertificates, &TLSInfo{
		Version:     tls.VersionName(st.Version),
		CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		ALPN:        st.NegotiatedProtocol,
		SNI:         sni,
		HandshakeMS: time.Since(start).Milliseconds(),
	}, nil
}

func cleanErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func consistency(results []IPResult) Consistency {
	groups := map[string][]string{}
	var keys []string
	for _, r := range results {
		if r.chainKey == "" {
			continue
		}
		if _, ok := groups[r.chainKey]; !ok {
			keys = append(keys, r.chainKey)
		}
		groups[r.chainKey] = append(groups[r.chainKey], r.IP)
	}
	c := Consistency{}
	for _, k := range keys {
		c.Groups = append(c.Groups, groups[k])
	}
	switch {
	case len(keys) == 0:
		c.Status, c.Detail = analyze.Info, "No chains to compare."
	case len(keys) == 1 && len(groups[keys[0]]) == 1:
		c.Status, c.Detail = analyze.Info, "Only one IP was tested."
	case len(keys) == 1:
		c.Status, c.Detail = analyze.Pass, identicalDetail(len(groups[keys[0]]))
	default:
		c.Status, c.Detail = analyze.Warn, fmt.Sprintf("The IPs serve %d different chains. Check for a server behind the load balancer that is set up differently.", len(keys))
	}
	return c
}

// Cost returns the rate-limit token cost for probing n IPs.
func Cost(n int) int { return 1 + n/4 }

func identicalDetail(n int) string {
	if n == 2 {
		return "Both reachable IPs serve an identical chain."
	}
	return fmt.Sprintf("All %d reachable IPs serve an identical chain.", n)
}
