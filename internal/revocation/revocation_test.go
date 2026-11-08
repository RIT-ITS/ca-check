package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"ca-chain-check/internal/analyze"
	"ca-chain-check/internal/netguard"
	"ca-chain-check/internal/testpki"
)

type allowAll struct{}

func (allowAll) CheckTarget(netip.Addr, netip.Addr) error { return nil }

// fakeCA serves an OCSP responder and a CRL for issuer, with the given
// serials revoked. It counts requests so caching can be checked.
type fakeCA struct {
	srv          *httptest.Server
	issuer       *testpki.Cert
	revoked      map[string]bool
	ocspHits     atomic.Int32
	crlHits      atomic.Int32
	crlSigner    *testpki.Cert // defaults to issuer
	ocspDown     bool
	nextUpdateIn time.Duration
}

func newFakeCA(t *testing.T, issuer *testpki.Cert) *fakeCA {
	f := &fakeCA{issuer: issuer, revoked: map[string]bool{}, nextUpdateIn: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ocsp", func(w http.ResponseWriter, r *http.Request) {
		f.ocspHits.Add(1)
		if f.ocspDown {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		req, err := ocsp.ParseRequest(body[:n])
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(f.nextUpdateIn)}
		if f.revoked[req.SerialNumber.String()] {
			tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, time.Now().Add(-48*time.Hour), ocsp.KeyCompromise
		}
		resp, err := ocsp.CreateResponse(f.issuer.Cert, f.issuer.Cert, tmpl, f.issuer.Key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(resp)
	})
	mux.HandleFunc("GET /ca.crl", func(w http.ResponseWriter, r *http.Request) {
		f.crlHits.Add(1)
		var entries []x509.RevocationListEntry
		for s := range f.revoked {
			n, _ := new(big.Int).SetString(s, 10)
			entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: time.Now().Add(-48 * time.Hour), ReasonCode: 4})
		}
		signer := f.crlSigner
		if signer == nil {
			signer = f.issuer
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: time.Now().Add(-3 * time.Hour), NextUpdate: time.Now().Add(f.nextUpdateIn),
			RevokedCertificateEntries: entries,
		}, signer.Cert, signer.Key)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = w.Write(der)
	})
	mux.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// url gives a URL on port 80 at a documentation-range address. The checker
// only allows ports 80 and 443, so the test dialer sends it to the real test
// server instead.
func (f *fakeCA) url(path string) string { return "http://192.0.2.10" + path }

func (f *fakeCA) checker(g Guard) *Checker {
	addr := f.srv.Listener.Addr().String()
	return &Checker{
		Guard: g, Timeout: 3 * time.Second,
		Dial: func(ctx context.Context, network, target string) (net.Conn, error) {
			if !strings.HasPrefix(target, "192.0.2.10:") {
				return nil, errors.New("test dialer: unexpected target " + target)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

func setup(t *testing.T) (*fakeCA, *testpki.Cert, *testpki.Cert, *testpki.Cert) {
	root := testpki.Root("Rev Root")
	inter := testpki.Intermediate("Rev Intermediate", root)
	f := newFakeCA(t, inter)
	good := testpki.Leaf("good.example.test", inter, testpki.Opts{OCSP: []string{f.url("/ocsp")}, CRL: []string{f.url("/ca.crl")}})
	bad := testpki.Leaf("revoked.example.test", inter, testpki.Opts{OCSP: []string{f.url("/ocsp")}, CRL: []string{f.url("/ca.crl")}})
	f.revoked[bad.Cert.SerialNumber.String()] = true
	return f, inter, good, bad
}

var client = netip.MustParseAddr("203.0.113.5")

func TestGoodAndRevoked(t *testing.T) {
	f, inter, good, bad := setup(t)
	check := f.checker(allowAll{}).For(t.Context(), client)

	r := check(good.Cert, inter.Cert)
	if r.OCSP == nil || r.OCSP.Status != analyze.RevGood || r.CRL == nil || r.CRL.Status != analyze.RevGood {
		t.Fatalf("good cert: ocsp %+v crl %+v", r.OCSP, r.CRL)
	}
	if r.CRL.NextUpdate == nil || r.OCSP.ThisUpdate == nil {
		t.Errorf("update times missing: %+v %+v", r.OCSP, r.CRL)
	}

	r = check(bad.Cert, inter.Cert)
	if r.OCSP.Status != analyze.RevRevoked || r.OCSP.Reason != "key compromise" || r.OCSP.RevokedAt == nil {
		t.Errorf("OCSP should report revoked: %+v", r.OCSP)
	}
	if r.CRL.Status != analyze.RevRevoked || r.CRL.Reason != "superseded" {
		t.Errorf("CRL should report revoked: %+v", r.CRL)
	}
	if r.Revoked() == nil {
		t.Error("Revoked() = nil")
	}
}

func TestCaching(t *testing.T) {
	f, inter, good, bad := setup(t)
	c := f.checker(allowAll{})
	for i := 0; i < 3; i++ {
		c.For(t.Context(), client)(good.Cert, inter.Cert)
		c.For(t.Context(), client)(bad.Cert, inter.Cert)
	}
	if n := f.crlHits.Load(); n != 1 {
		t.Errorf("CRL fetched %d times, want 1", n)
	}
	if n := f.ocspHits.Load(); n != 2 {
		t.Errorf("OCSP fetched %d times, want 2 (one per certificate)", n)
	}
}

func TestWrongCRLSignerAndResponderDown(t *testing.T) {
	f, inter, good, _ := setup(t)
	f.crlSigner = testpki.Intermediate("Impostor", testpki.Root("Other Root"))
	f.ocspDown = true
	r := f.checker(allowAll{}).For(t.Context(), client)(good.Cert, inter.Cert)
	if r.CRL.Status != analyze.RevError || !strings.Contains(r.CRL.Error, "not signed by the issuer") {
		t.Errorf("CRL from the wrong signer must not be trusted: %+v", r.CRL)
	}
	if r.OCSP.Status != analyze.RevError || !strings.Contains(r.OCSP.Error, "HTTP 503") {
		t.Errorf("responder down: %+v", r.OCSP)
	}
}

func TestStaleCRL(t *testing.T) {
	f, inter, good, _ := setup(t)
	f.nextUpdateIn = -time.Hour
	r := f.checker(allowAll{}).For(t.Context(), client)(good.Cert, inter.Cert)
	if r.CRL.Status != analyze.RevError || !strings.Contains(r.CRL.Error, "out of date") {
		t.Errorf("stale CRL: %+v", r.CRL)
	}
}

// The URLs come from the certificate, so the target policy must apply:
// internal addresses, other ports, other schemes and redirects into
// blocked ranges are all refused.
func TestPolicy(t *testing.T) {
	f, inter, _, _ := setup(t)
	deny := netguard.New(nil, nil, nil, nil, false)
	cases := map[string][]string{
		"loopback": {"http://127.0.0.1/ocsp", "private address"},
		"metadata": {"http://169.254.169.254/latest", "routable"},
		"port":     {"http://192.0.2.10:8080/ca.crl", "only 80 and 443"},
		"redirect": {f.url("/redirect"), "routable"},
		"userinfo": {"http://user:pw@192.0.2.10/ca.crl", "credentials"},
	}
	for name, c := range cases {
		cert := testpki.Leaf(name+".example.test", inter, testpki.Opts{CRL: []string{c[0]}})
		r := f.checker(deny).For(t.Context(), client)(cert.Cert, inter.Cert)
		if r.CRL == nil || r.CRL.Status != analyze.RevError || !strings.Contains(r.CRL.Error, c[1]) {
			t.Errorf("%s: %+v", name, r.CRL)
		}
	}
	// LDAP-only distribution points are skipped, not fetched.
	cert := testpki.Leaf("ldap.example.test", inter, testpki.Opts{CRL: []string{"ldap://ldap.example.test/cn=crl"}})
	if r := f.checker(deny).For(t.Context(), client)(cert.Cert, inter.Cert); r.CRL != nil {
		t.Errorf("ldap CRL should be skipped: %+v", r.CRL)
	}
}

// End to end through the analyzer: the check, the certificate fields and
// the diagram all report the revoked leaf.
func TestAnalyzeReportsRevocation(t *testing.T) {
	f, inter, good, bad := setup(t)
	c := f.checker(allowAll{})
	for _, tc := range []struct {
		leaf   *testpki.Cert
		status string
	}{{good, analyze.Pass}, {bad, analyze.Fail}} {
		res := analyze.Analyze(testpki.X509(tc.leaf, inter), analyze.Options{Now: time.Now(), Revocation: c.For(t.Context(), client)})
		var chk *analyze.Check
		for i := range res.Checks {
			if res.Checks[i].ID == "revocation" {
				chk = &res.Checks[i]
			}
		}
		if chk == nil {
			t.Fatal("no revocation check")
		}
		// The intermediate's issuer is not in the chain, so only the leaf is checked.
		if chk.Status != tc.status {
			t.Errorf("%s: status %s (%s %v)", tc.leaf.Cert.Subject.CommonName, chk.Status, chk.Detail, chk.Items)
		}
		if tc.status == analyze.Fail {
			if len(chk.Items) != 1 || !strings.Contains(chk.Items[0], "revoked on") {
				t.Errorf("items %v", chk.Items)
			}
			if !strings.Contains(res.Mermaid, "<br/>revoked") || !strings.Contains(res.Mermaid, "class c0 bad") {
				t.Errorf("diagram does not show the revoked leaf:\n%s", res.Mermaid)
			}
		}
	}
}
