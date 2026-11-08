// Package revocation asks a certificate's issuer whether it is revoked,
// through the OCSP responder and CRL named in the certificate.
//
// The URLs come from certificates that anyone can make, so every fetch is
// treated like a probe target: only http and https on ports 80 and 443,
// every resolved address passes the same target policy (netguard) before
// a connection is made, redirects are re-checked, and responses are size-
// and time-limited. Answers are cached until the issuer's next update, at
// most an hour.
package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"ca-chain-check/internal/analyze"
)

const (
	maxOCSPBytes = 64 << 10
	maxCRLBytes  = 20 << 20
	maxCacheTTL  = time.Hour
	maxCacheCRLs = 64
	maxRedirects = 3
)

// Guard decides whether an address may be contacted for this client.
type Guard interface {
	CheckTarget(client, target netip.Addr) error
}

// Checker fetches and caches OCSP responses and CRLs.
type Checker struct {
	Guard       Guard
	Resolver    *net.Resolver
	Timeout     time.Duration // per fetch
	DisableIPv6 bool
	// Dial is overridable for tests; it must connect to exactly addr.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	Now  func() time.Time

	mu       sync.Mutex
	ocspSeen map[string]cached[*analyze.RevocationSource]
	crls     map[string]cached[*crlEntry]
	inflight map[string]*sync.WaitGroup
}

type cached[T any] struct {
	v       T
	expires time.Time
}

type crlEntry struct {
	revoked    map[string]x509.RevocationListEntry // by serial, decimal
	thisUpdate time.Time
	nextUpdate time.Time
	err        error
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// For returns a function suitable for analyze.Options.Revocation that checks
// on behalf of client, giving up when ctx ends.
func (c *Checker) For(ctx context.Context, client netip.Addr) func(cert, issuer *x509.Certificate) *analyze.Revocation {
	return func(cert, issuer *x509.Certificate) *analyze.Revocation {
		r := &analyze.Revocation{}
		var wg sync.WaitGroup
		if u := firstHTTP(cert.OCSPServer); u != "" {
			wg.Add(1)
			go func() { defer wg.Done(); r.OCSP = c.ocsp(ctx, client, u, cert, issuer) }()
		}
		if u := firstHTTP(cert.CRLDistributionPoints); u != "" {
			wg.Add(1)
			go func() { defer wg.Done(); r.CRL = c.crl(ctx, client, u, cert, issuer) }()
		}
		wg.Wait()
		return r
	}
}

// firstHTTP picks the first http(s) URL; LDAP and other schemes are skipped.
func firstHTTP(urls []string) string {
	for _, u := range urls {
		l := strings.ToLower(u)
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			return u
		}
	}
	return ""
}

func errSource(u string, err error) *analyze.RevocationSource {
	return &analyze.RevocationSource{URL: u, Status: analyze.RevError, Error: err.Error()}
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

// ---------- OCSP ----------

func (c *Checker) ocsp(ctx context.Context, client netip.Addr, u string, cert, issuer *x509.Certificate) *analyze.RevocationSource {
	key := u + "|" + string(issuer.RawSubjectPublicKeyInfo) + "|" + cert.SerialNumber.String()
	c.mu.Lock()
	if e, ok := c.ocspSeen[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.v
	}
	c.mu.Unlock()

	src := c.fetchOCSP(ctx, client, u, cert, issuer)
	if src.Status != analyze.RevError {
		exp := c.now().Add(maxCacheTTL)
		if src.NextUpdate != nil && src.NextUpdate.Before(exp) {
			exp = *src.NextUpdate
		}
		c.mu.Lock()
		if c.ocspSeen == nil || len(c.ocspSeen) > 4096 {
			c.ocspSeen = map[string]cached[*analyze.RevocationSource]{}
		}
		c.ocspSeen[key] = cached[*analyze.RevocationSource]{src, exp}
		c.mu.Unlock()
	}
	return src
}

func (c *Checker) fetchOCSP(ctx context.Context, client netip.Addr, u string, cert, issuer *x509.Certificate) *analyze.RevocationSource {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return errSource(u, fmt.Errorf("building request: %w", err))
	}
	body, err := c.fetch(ctx, client, http.MethodPost, u, "application/ocsp-request", req, maxOCSPBytes)
	if err != nil {
		return errSource(u, err)
	}
	resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return errSource(u, fmt.Errorf("invalid response: %w", err))
	}
	src := &analyze.RevocationSource{URL: u, ThisUpdate: tp(resp.ThisUpdate), NextUpdate: tp(resp.NextUpdate)}
	switch resp.Status {
	case ocsp.Good:
		src.Status = analyze.RevGood
	case ocsp.Revoked:
		src.Status = analyze.RevRevoked
		src.RevokedAt = tp(resp.RevokedAt)
		src.Reason = reasonName(resp.RevocationReason)
	default:
		src.Status = analyze.RevUnknown
	}
	if src.Status == analyze.RevGood && !resp.NextUpdate.IsZero() && c.now().After(resp.NextUpdate) {
		return errSource(u, fmt.Errorf("response is out of date (next update was %s)", resp.NextUpdate.UTC().Format("2006-01-02 15:04 MST")))
	}
	return src
}

// ---------- CRL ----------

func (c *Checker) crl(ctx context.Context, client netip.Addr, u string, cert, issuer *x509.Certificate) *analyze.RevocationSource {
	key := u + "|" + string(issuer.RawSubjectPublicKeyInfo)
	e := c.crlFor(ctx, client, u, key, issuer)
	if e.err != nil {
		return errSource(u, e.err)
	}
	src := &analyze.RevocationSource{URL: u, Status: analyze.RevGood, ThisUpdate: tp(e.thisUpdate), NextUpdate: tp(e.nextUpdate)}
	if ent, ok := e.revoked[cert.SerialNumber.String()]; ok {
		src.Status = analyze.RevRevoked
		src.RevokedAt = tp(ent.RevocationTime)
		src.Reason = reasonName(ent.ReasonCode)
		return src
	}
	if !e.nextUpdate.IsZero() && c.now().After(e.nextUpdate) {
		return errSource(u, fmt.Errorf("CRL is out of date (next update was %s)", e.nextUpdate.UTC().Format("2006-01-02 15:04 MST")))
	}
	return src
}

// crlFor returns the parsed, signature-checked CRL, fetching it at most once
// at a time per URL and issuer.
func (c *Checker) crlFor(ctx context.Context, client netip.Addr, u, key string, issuer *x509.Certificate) *crlEntry {
	for {
		c.mu.Lock()
		if e, ok := c.crls[key]; ok && c.now().Before(e.expires) {
			c.mu.Unlock()
			return e.v
		}
		if wg, busy := c.inflight[key]; busy {
			c.mu.Unlock()
			wg.Wait()
			continue
		}
		if c.inflight == nil {
			c.inflight = map[string]*sync.WaitGroup{}
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.inflight[key] = wg
		c.mu.Unlock()

		e := c.fetchCRL(ctx, client, u, issuer)
		exp := c.now().Add(maxCacheTTL)
		if e.err != nil {
			exp = c.now().Add(time.Minute) // retry failures soon, but not on every check
		} else if !e.nextUpdate.IsZero() && e.nextUpdate.Before(exp) && e.nextUpdate.After(c.now()) {
			exp = e.nextUpdate
		}
		c.mu.Lock()
		if c.crls == nil || len(c.crls) >= maxCacheCRLs {
			c.crls = map[string]cached[*crlEntry]{}
		}
		c.crls[key] = cached[*crlEntry]{e, exp}
		delete(c.inflight, key)
		c.mu.Unlock()
		wg.Done()
		return e
	}
}

func (c *Checker) fetchCRL(ctx context.Context, client netip.Addr, u string, issuer *x509.Certificate) *crlEntry {
	body, err := c.fetch(ctx, client, http.MethodGet, u, "", nil, maxCRLBytes)
	if err != nil {
		return &crlEntry{err: err}
	}
	if blk, _ := pem.Decode(body); blk != nil && blk.Type == "X509 CRL" {
		body = blk.Bytes
	}
	rl, err := x509.ParseRevocationList(body)
	if err != nil {
		return &crlEntry{err: fmt.Errorf("invalid CRL: %w", err)}
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return &crlEntry{err: fmt.Errorf("CRL is not signed by the issuer: %w", err)}
	}
	e := &crlEntry{revoked: make(map[string]x509.RevocationListEntry, len(rl.RevokedCertificateEntries)), thisUpdate: rl.ThisUpdate, nextUpdate: rl.NextUpdate}
	for _, ent := range rl.RevokedCertificateEntries {
		e.revoked[ent.SerialNumber.String()] = ent
	}
	return e
}

// ---------- HTTP ----------

var errPolicy = errors.New("blocked by policy")

// fetch performs one request under the target policy, following at most a
// few redirects, each checked the same way.
func (c *Checker) fetch(ctx context.Context, client netip.Addr, method, raw, contentType string, body []byte, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	for hop := 0; ; hop++ {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("bad URL: %w", err)
		}
		if err := allowedURL(u); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("User-Agent", "ca-chain-check")
		resp, err := c.httpClient(client).Do(req)
		if err != nil {
			return nil, cleanErr(err)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
			resp.Body.Close()
			if hop >= maxRedirects {
				return nil, errors.New("too many redirects")
			}
			next, err := u.Parse(resp.Header.Get("Location"))
			if err != nil {
				return nil, fmt.Errorf("bad redirect: %w", err)
			}
			raw = next.String()
			if method == http.MethodPost && resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
				method, body, contentType = http.MethodGet, nil, ""
			}
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, u.Host)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, cleanErr(err)
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("response larger than %d KB", limit>>10)
		}
		return data, nil
	}
}

func allowedURL(u *url.URL) error {
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("%w: scheme %q", errPolicy, u.Scheme)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if port != "80" && port != "443" {
		return fmt.Errorf("%w: port %s (only 80 and 443)", errPolicy, port)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL", errPolicy)
	}
	return nil
}

func (c *Checker) httpClient(client netip.Addr) *http.Client {
	tr := &http.Transport{
		Proxy:                  nil, // never through an environment proxy: the policy is per address
		DialContext:            c.guardedDial(client),
		TLSHandshakeTimeout:    c.Timeout,
		ResponseHeaderTimeout:  c.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: tr,
		// fetch follows redirects itself so each hop is re-checked.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// guardedDial resolves the host itself and connects only to addresses the
// target policy allows, so DNS can't point a fetch at an internal service.
func (c *Checker) guardedDial(client netip.Addr) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ips []netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{a}
		} else {
			res := c.Resolver
			if res == nil {
				res = net.DefaultResolver
			}
			nw := "ip"
			if c.DisableIPv6 {
				nw = "ip4"
			}
			ips, err = res.LookupNetIP(ctx, nw, host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup for %s failed", host)
			}
		}
		dial := c.Dial
		if dial == nil {
			d := &net.Dialer{}
			dial = d.DialContext
		}
		var last error = fmt.Errorf("%s has no usable address", host)
		for _, ip := range ips {
			ip = ip.Unmap()
			if c.DisableIPv6 && ip.Is6() {
				continue
			}
			if err := c.Guard.CheckTarget(client, ip); err != nil {
				last = fmt.Errorf("%w: %v", errPolicy, err)
				continue
			}
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}

func cleanErr(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("timed out")
	}
	if errors.Is(err, errPolicy) {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// reasonName turns an RFC 5280 CRLReason code into words.
func reasonName(code int) string {
	names := map[int]string{
		0: "", 1: "key compromise", 2: "CA compromise", 3: "affiliation changed",
		4: "superseded", 5: "cessation of operation", 6: "certificate hold",
		8: "remove from CRL", 9: "privilege withdrawn", 10: "AA compromise",
	}
	if n, ok := names[code]; ok {
		return n
	}
	return "reason " + strconv.Itoa(code)
}
