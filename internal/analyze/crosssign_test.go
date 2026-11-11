package analyze

import (
	"strings"
	"testing"
	"time"

	"ca-chain-check/internal/testpki"
	"ca-chain-check/internal/truststore"
)

type crossPKI struct {
	oldRoot, newRoot, cross, inter, leaf *testpki.Cert
}

func newCrossPKI(o ...testpki.Opts) crossPKI {
	oldRoot := testpki.Root("Old Root")
	newRoot := testpki.Root("New Root")
	co := testpki.Opts{Key: newRoot.Key}
	if len(o) > 0 {
		co.NotBefore, co.NotAfter = o[0].NotBefore, o[0].NotAfter
	}
	cross := testpki.Intermediate("New Root", oldRoot, co)
	inter := testpki.Intermediate("Issuing CA", newRoot)
	leaf := testpki.Leaf("www.example.test", inter)
	return crossPKI{oldRoot, newRoot, cross, inter, leaf}
}

func notSentPaths(r *Result) []Path {
	var out []Path
	for _, p := range r.Paths {
		if p.NotSent {
			out = append(out, p)
		}
	}
	return out
}

// The server sends leaf and intermediate only; the cross-sign comes from
// the CCADB pool and adds an information-only path to the other root.
func TestCrossSignFromPoolAddsNotSentPath(t *testing.T) {
	k := newCrossPKI()
	s := truststore.NewFromCerts(testpki.X509(k.oldRoot, k.newRoot), "test")
	s.SetCrossSigns(testpki.X509(k.cross))
	r := Analyze(testpki.X509(k.leaf, k.inter), opts(s))

	ns := notSentPaths(r)
	if len(ns) != 1 || len(ns[0].Nodes) != 4 || !ns[0].Trusted || ns[0].Best {
		t.Fatalf("not-sent paths = %+v", ns)
	}
	if !r.Paths[0].Best || r.Paths[0].NotSent || len(r.Paths[0].Nodes) != 3 {
		t.Errorf("best path should be the sent one: %+v", r.Paths[0])
	}
	if !r.Paths[len(r.Paths)-1].NotSent {
		t.Error("not-sent paths should come last")
	}
	if len(r.StoreRoots) != 1 || r.StoreRoots[0].SubjectCN != "New Root" {
		t.Errorf("store roots = %+v", r.StoreRoots)
	}
	var src []string
	for _, c := range r.CrossSigns {
		src = append(src, c.Source+":"+c.SubjectCN)
	}
	if strings.Join(src, ",") != "ccadb:New Root,mozilla_store:Old Root" {
		t.Errorf("cross signs = %v", src)
	}
	wantStatus(t, r, "mozilla_root", Pass)
	wantStatus(t, r, "extra_certs", Pass)
	if !strings.Contains(r.Mermaid, "cross-sign (not sent)") || !strings.Contains(r.Mermaid, "-.->") {
		t.Errorf("diagram does not show the cross-sign:\n%s", r.Mermaid)
	}
	found := false
	for _, e := range r.DiagramKey {
		found = found || e.ID == "crosssign"
	}
	if !found {
		t.Errorf("diagram key lacks crosssign: %+v", r.DiagramKey)
	}
}

// A cross-sign the server sends stays "presented" and is not duplicated
// from the pool.
func TestCrossSignSentIsNotDuplicated(t *testing.T) {
	k := newCrossPKI()
	s := truststore.NewFromCerts(testpki.X509(k.oldRoot, k.newRoot), "test")
	s.SetCrossSigns(testpki.X509(k.cross))
	r := Analyze(testpki.X509(k.leaf, k.inter, k.cross), opts(s))
	if ns := notSentPaths(r); len(ns) != 0 {
		t.Errorf("unexpected not-sent paths: %+v", ns)
	}
	if len(r.CrossSigns) != 0 {
		t.Errorf("cross signs = %+v", r.CrossSigns)
	}
	if n := countTrusted(r.Paths); n != 2 {
		t.Errorf("trusted paths = %d, want 2", n)
	}
}

func TestCrossSignExpiredIgnored(t *testing.T) {
	k := newCrossPKI(testpki.Opts{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	s := truststore.NewFromCerts(testpki.X509(k.oldRoot, k.newRoot), "test")
	s.SetCrossSigns(testpki.X509(k.cross))
	r := Analyze(testpki.X509(k.leaf, k.inter), opts(s))
	if ns := notSentPaths(r); len(ns) != 0 {
		t.Errorf("expired cross-sign used: %+v", ns)
	}
}

// The pool never fills in an intermediate the server left out.
func TestCrossSignPoolDoesNotCompleteChain(t *testing.T) {
	k := newCrossPKI()
	s := truststore.NewFromCerts(testpki.X509(k.oldRoot, k.newRoot), "test")
	// Put the issuing CA in the candidate list too: it is not a cross-sign
	// of a root, so the store must drop it.
	s.SetCrossSigns(testpki.X509(k.cross, k.inter))
	if n := len(s.CrossSigns()); n != 1 {
		t.Fatalf("store kept %d cross-signs, want 1", n)
	}
	r := Analyze(testpki.X509(k.leaf), opts(s))
	wantStatus(t, r, "mozilla_root", Fail)
	if len(r.Paths) != 1 || r.Paths[0].Terminal != TermIncomplete {
		t.Errorf("paths = %+v", r.Paths)
	}
}

// Trust through a cross-sign the server doesn't send doesn't count.
func TestCrossSignPoolDoesNotChangeTrust(t *testing.T) {
	k := newCrossPKI()
	m := map[string]map[string]string{
		truststore.FingerprintSHA256(k.oldRoot.Cert): {truststore.Microsoft: truststore.Trusted},
		truststore.FingerprintSHA256(k.newRoot.Cert): {truststore.Apple: truststore.Trusted, truststore.Chrome: truststore.Trusted, truststore.Mozilla: truststore.Trusted},
	}
	s := truststore.NewWithTrust(testpki.X509(k.oldRoot, k.newRoot), m, "test")
	s.SetCrossSigns(testpki.X509(k.cross))
	r := Analyze(testpki.X509(k.leaf, k.inter), opts(s))
	wantStatus(t, r, "mozilla_root", Warn)
	for _, st := range r.TrustStores {
		if st.Store == truststore.Microsoft && st.Status != "untrusted" {
			t.Errorf("Microsoft = %s, want untrusted", st.Status)
		}
	}
	if ns := notSentPaths(r); len(ns) != 1 || len(ns[0].Stores) != 1 || ns[0].Stores[0] != truststore.Microsoft {
		t.Errorf("not-sent path should show Microsoft trust: %+v", ns)
	}
}
