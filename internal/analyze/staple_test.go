package analyze

import (
	"testing"
	"time"

	"ca-chain-check/internal/testpki"
	"ca-chain-check/internal/truststore"
	"golang.org/x/crypto/ocsp"
)

// stapleFor signs an OCSP response for leaf with its issuer.
func stapleFor(t *testing.T, leaf, issuer *testpki.Cert, status int, this, next time.Time) []byte {
	t.Helper()
	tmpl := ocsp.Response{Status: status, SerialNumber: leaf.Cert.SerialNumber, ThisUpdate: this, NextUpdate: next}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = this.Add(-time.Hour)
	}
	b, err := ocsp.CreateResponse(issuer.Cert, issuer.Cert, tmpl, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stapleCase(t *testing.T, mustStaple bool, staple func(leaf, inter *testpki.Cert) []byte) (*Result, Check) {
	t.Helper()
	root := testpki.Root("Staple Root")
	inter := testpki.Intermediate("Staple CA", root)
	leaf := testpki.Leaf("www.example.test", inter, testpki.Opts{OCSP: []string{"http://ocsp.example.test"}, MustStaple: mustStaple})
	o := opts(truststore.NewFromCerts(testpki.X509(root), "test"))
	if staple != nil {
		o.Staple = staple(leaf, inter)
	}
	r := Analyze(testpki.X509(leaf, inter), o)
	return r, check(t, r, "ocsp_stapling")
}

func TestStapling(t *testing.T) {
	now := time.Now()
	good := func(l, i *testpki.Cert) []byte { return stapleFor(t, l, i, ocsp.Good, now.Add(-time.Hour), now.Add(48*time.Hour)) }
	stale := func(l, i *testpki.Cert) []byte { return stapleFor(t, l, i, ocsp.Good, now.Add(-72*time.Hour), now.Add(-time.Hour)) }
	revoked := func(l, i *testpki.Cert) []byte { return stapleFor(t, l, i, ocsp.Revoked, now.Add(-time.Hour), now.Add(48*time.Hour)) }
	wrongCert := func(_, i *testpki.Cert) []byte {
		other := testpki.Leaf("other.example.test", testpki.Intermediate("Other CA", testpki.Root("Other Root")))
		return stapleFor(t, other, i, ocsp.Good, now.Add(-time.Hour), now.Add(48*time.Hour))
	}
	for _, tc := range []struct {
		name   string
		must   bool
		staple func(l, i *testpki.Cert) []byte
		want   string
		status string
	}{
		{"none", false, nil, Pass, ""},
		{"none, must-staple", true, nil, Fail, ""},
		{"good", false, good, Pass, RevGood},
		{"good, must-staple", true, good, Pass, RevGood},
		{"stale", false, stale, Warn, RevError},
		{"stale, must-staple", true, stale, Fail, RevError},
		{"revoked", false, revoked, Fail, RevRevoked},
		{"garbage", false, func(_, _ *testpki.Cert) []byte { return []byte("not ocsp") }, Warn, RevError},
		{"for another certificate", false, wrongCert, Warn, RevError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c := stapleCase(t, tc.must, tc.staple)
			if c.Status != tc.want || r.Staple.Status != tc.status || r.Staple.MustStaple != tc.must {
				t.Errorf("check %s %q, staple %+v", c.Status, c.Detail, r.Staple)
			}
		})
	}
}
