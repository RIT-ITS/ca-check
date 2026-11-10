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
	"ca-chain-check/internal/revocation"
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
	// StartTLS names a protocol (see StartTLSPorts) whose plain-text upgrade
	// runs before the TLS handshake; "none" means TLS from the first byte
	// only. Empty means automatic: TLS first, then STARTTLS if the port is
	// a common STARTTLS port (AutoStartTLS) and the TLS handshake failed.
	StartTLS string `json:"starttls,omitempty"`
	// Fallback is set by Plan: the STARTTLS protocol to try when TLS fails.
	Fallback string `json:"-"`
}

// TLSInfo describes the negotiated session.
type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipherSuite"`
	ALPN        string `json:"alpn,omitempty"`
	SNI         string `json:"sni,omitempty"`
	HandshakeMS int64  `json:"handshakeMs"`
	StartTLS    string `json:"starttls,omitempty"` // protocol used, if any
	staple      []byte // stapled OCSP response, if any
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
	// KeyType is the leaf's key type: "rsa", "ecdsa" or "other".
	KeyType string `json:"keyType,omitempty"`
	// Alternate is the chain the server sends to clients that ask for the
	// other key type, when it has a second certificate.
	Alternate *AltResult `json:"alternate,omitempty"`
	// KeyTypeNote explains why there is no Alternate.
	KeyTypeNote string `json:"keyTypeNote,omitempty"`
	chainKey    string
}

// AltResult is the second chain of a server with both an RSA and an ECDSA
// certificate.
type AltResult struct {
	KeyType  string          `json:"keyType"`
	TLS      *TLSInfo        `json:"tls"`
	Analysis *analyze.Result `json:"analysis"`
	Overall  string          `json:"overall"`
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
	StartTLS    string          `json:"starttls,omitempty"`         // requested protocol
	Fallback    string          `json:"starttlsFallback,omitempty"` // tried when TLS fails
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
	// Revocation checks OCSP and CRLs when set.
	Revocation *revocation.Checker
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
	req.StartTLS = strings.ToLower(strings.TrimSpace(req.StartTLS))
	switch req.StartTLS {
	case "none":
		req.StartTLS = "" // explicit plain TLS, even on a STARTTLS port
	case "":
		if req.Port == 0 {
			req.Port = 443
		}
		if proto, ok := DirectStartTLS[req.Port]; ok {
			req.StartTLS = proto
		} else {
			req.Fallback = AutoStartTLS[req.Port]
		}
	default:
		def, ok := StartTLSPorts[req.StartTLS]
		if !ok {
			err = inputErr("unsupported STARTTLS protocol %q (use none or one of: %s)", req.StartTLS, strings.Join(StartTLSNames(), ", "))
			return
		}
		if req.Port == 0 {
			req.Port = def
		}
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
func (p *Prober) Run(ctx context.Context, client netip.Addr, host string, port int, starttls, fallback string, ips []netip.Addr, res Resolution) *Response {
	resp := &Response{Host: host, Port: port, StartTLS: starttls, Fallback: fallback, CheckedAt: time.Now().UTC(), Resolution: res, TrustStore: p.Store.Info()}
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
			p.probeOne(ctx, client, r, host, port, starttls, fallback, ip)
		}(&resp.Results[i], ip)
	}
	wg.Wait()
	resp.Consistency = consistency(resp.Results)
	return resp
}

func (p *Prober) probeOne(ctx context.Context, client netip.Addr, r *IPResult, host string, port int, starttls, fallback string, ip netip.Addr) {
	select {
	case p.Sem <- struct{}{}:
		defer func() { <-p.Sem }()
	case <-ctx.Done():
		r.Error = "server busy: " + ctx.Err().Error()
		r.Overall = analyze.Fail
		return
	}
	r.Tested = true
	certs, info, err := p.handshake(ctx, host, port, starttls, fallback, ip)
	if err != nil {
		r.Error = err.Error()
		r.Overall = analyze.Fail
		return
	}
	r.TLS = info
	r.KeyType = keyType(certs[0])

	// Ask for the other key type's certificate.
	var altCerts []*x509.Certificate
	var altInfo *TLSInfo
	if want := otherKeyType(r.KeyType); p.Cfg.CheckAltKeyType && want != "" {
		altCerts, altInfo, err = p.attempt(ctx, host, port, info.StartTLS, ip, want)
		switch {
		case err != nil:
			r.KeyTypeNote = altFailNote(r.KeyType, want, err)
			altCerts = nil
		case keyType(altCerts[0]) != want:
			r.KeyTypeNote = fmt.Sprintf("The server has only an %s certificate.", keyTypeName(r.KeyType))
			altCerts = nil
		}
	}

	var rev func(cert, issuer *x509.Certificate) *analyze.Revocation
	if p.Revocation != nil {
		rev = p.Revocation.For(ctx, client)
	}
	analyzeChain := func(certs []*x509.Certificate, info *TLSInfo) *analyze.Result {
		return analyze.Analyze(certs, analyze.Options{
			Revocation:     rev,
			Host:           host, // VerifyHostname also handles IP-literal SANs
			Now:            time.Now(),
			ExpiringSoon:   time.Duration(p.Cfg.ExpiringSoonDays) * 24 * time.Hour,
			Store:          p.Store,
			Pending:        p.Cfg.PendingDistrust,
			RequiredStores: p.Cfg.RequiredStores,
			Staple:         info.staple,
		})
	}
	var wg sync.WaitGroup
	if altCerts != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alt := &AltResult{KeyType: keyType(altCerts[0]), TLS: altInfo, Analysis: analyzeChain(altCerts, altInfo)}
			alt.Overall = alt.Analysis.Overall
			r.Alternate = alt
		}()
	}
	r.Analysis = analyzeChain(certs, info)
	wg.Wait()
	r.Overall = r.Analysis.Overall
	key := chainKey(r.Analysis)
	if r.Alternate != nil {
		r.Overall = analyze.Worst(r.Overall, r.Alternate.Overall)
		key += "|" + chainKey(r.Alternate.Analysis)
	}
	r.chainKey = key
}

func chainKey(a *analyze.Result) string {
	var fps []string
	for _, c := range a.Chain {
		fps = append(fps, c.SHA256)
	}
	return strings.Join(fps, ",")
}

// keyType names the leaf's key type for choosing a certificate.
func keyType(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "rsa"
	case x509.ECDSA:
		return "ecdsa"
	}
	return "other"
}

func otherKeyType(t string) string {
	switch t {
	case "rsa":
		return "ecdsa"
	case "ecdsa":
		return "rsa"
	}
	return ""
}

func keyTypeName(t string) string {
	switch t {
	case "rsa":
		return "RSA"
	case "ecdsa":
		return "ECDSA"
	}
	return t
}

// altFailNote explains a failed handshake that asked for the other key type.
func altFailNote(have, want string, err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "protocol version"):
		return fmt.Sprintf("Could not check for an %s certificate: the server only allows TLS 1.3, and this check needs TLS 1.2 to ask for one.", keyTypeName(want))
	case strings.Contains(msg, "handshake failure"), strings.Contains(msg, "insufficient security"):
		return fmt.Sprintf("The server has only an %s certificate.", keyTypeName(have))
	}
	return fmt.Sprintf("Could not check for an %s certificate: %s", keyTypeName(want), msg)
}

// Cipher suites that make a TLS 1.2 server pick a certificate of one key type.
var suitesFor = map[string][]uint16{
	"ecdsa": {
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	},
	"rsa": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
}

// connectError marks a failure to open the TCP connection, which a STARTTLS
// retry cannot fix.
type connectError struct{ msg string }

func (e *connectError) Error() string { return e.msg }

// handshake fetches the chain. With starttls set it upgrades with that
// protocol. Otherwise it tries TLS from the first byte and, if that
// handshake fails and fallback names a protocol, reconnects and tries
// STARTTLS.
func (p *Prober) handshake(ctx context.Context, host string, port int, starttls, fallback string, ip netip.Addr) ([]*x509.Certificate, *TLSInfo, error) {
	certs, info, err := p.attempt(ctx, host, port, starttls, ip, "")
	var ce *connectError
	if err == nil || starttls != "" || fallback == "" || errors.As(err, &ce) || ctx.Err() != nil {
		return certs, info, err
	}
	certs, info, err2 := p.attempt(ctx, host, port, fallback, ip, "")
	if err2 == nil {
		return certs, info, nil
	}
	return nil, nil, fmt.Errorf("%s. STARTTLS (%s) also failed: %s", err, fallback, err2)
}

// attempt does one handshake. With only set ("rsa" or "ecdsa") it offers
// TLS 1.2 with just that key type's cipher suites, so a server with two
// certificates sends that one, and reads the chain without finishing the
// handshake (see fetchChain12).
func (p *Prober) attempt(ctx context.Context, host string, port int, starttls string, ip netip.Addr, only string) ([]*x509.Certificate, *TLSInfo, error) {
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
		return nil, nil, &connectError{fmt.Sprintf("connect to %s failed: %s", addr, cleanErr(err))}
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
	}
	start := time.Now()
	if starttls != "" {
		// The plain-text upgrade shares the handshake time budget.
		_ = raw.SetDeadline(start.Add(p.Cfg.HandshakeTimeout))
		if err := startTLS(raw, starttls); err != nil {
			return nil, nil, fmt.Errorf("STARTTLS (%s) upgrade with %s failed: %s", starttls, addr, cleanErr(err))
		}
		_ = raw.SetDeadline(time.Time{})
	} else {
		conf.NextProtos = []string{"h2", "http/1.1"}
	}
	if only != "" {
		// Read the other key type's chain with a hand-built TLS 1.2 hello.
		_ = raw.SetDeadline(start.Add(p.Cfg.HandshakeTimeout))
		hsStart := time.Now()
		ch, err := fetchChain12(raw, sni, suitesFor[only])
		if err != nil {
			return nil, nil, fmt.Errorf("TLS handshake with %s failed: %s", addr, cleanErr(err))
		}
		return ch.certs, &TLSInfo{
			Version:     tls.VersionName(tls.VersionTLS12),
			CipherSuite: tls.CipherSuiteName(ch.suite),
			SNI:         sni,
			HandshakeMS: time.Since(hsStart).Milliseconds(),
			StartTLS:    starttls,
			staple:      ch.staple,
		}, nil
	}
	conn := tls.Client(raw, conf)
	hctx, hcancel := context.WithDeadline(ctx, start.Add(p.Cfg.HandshakeTimeout))
	defer hcancel()
	hsStart := time.Now()
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
		HandshakeMS: time.Since(hsStart).Milliseconds(),
		StartTLS:    starttls,
		staple:      st.OCSPResponse,
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
