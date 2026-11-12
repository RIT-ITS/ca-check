package analyze

import (
	"strings"
	"testing"
	"time"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/testpki"
	"ca-chain-check/internal/truststore"
)

type pki struct {
	root, inter, leaf *testpki.Cert
	store             *truststore.Store
}

func newPKI() pki {
	root := testpki.Root("Test Root")
	inter := testpki.Intermediate("Test Intermediate", root)
	leaf := testpki.Leaf("www.example.test", inter)
	return pki{root, inter, leaf, truststore.NewFromCerts(testpki.X509(root), "test")}
}

func opts(store *truststore.Store) Options {
	return Options{Host: "www.example.test", Now: time.Now(), ExpiringSoon: 30 * 24 * time.Hour, Store: store}
}

func check(t *testing.T, r *Result, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not present; got %+v", id, r.Checks)
	return Check{}
}

func wantStatus(t *testing.T, r *Result, id, status string) {
	t.Helper()
	if c := check(t, r, id); c.Status != status {
		t.Errorf("check %s: status %s, want %s (detail %q items %v)", id, c.Status, status, c.Detail, c.Items)
	}
}

func TestCorrectChain(t *testing.T) {
	p := newPKI()
	r := Analyze(testpki.X509(p.leaf, p.inter), opts(p.store))
	for _, id := range []string{"mozilla_root", "order", "validity", "extra_certs", "pending_distrust", "hostname"} {
		wantStatus(t, r, id, Pass)
	}
	if r.Overall != Pass {
		t.Errorf("overall %s", r.Overall)
	}
	if len(r.Paths) != 1 || !r.Paths[0].Trusted || len(r.Paths[0].Nodes) != 3 {
		t.Fatalf("paths: %+v", r.Paths)
	}
	if len(r.StoreRoots) != 1 || r.StoreRoots[0].Index != -1 || !r.StoreRoots[0].OnTrustedPath {
		t.Errorf("store roots: %+v", r.StoreRoots)
	}
	if !strings.Contains(r.Mermaid, "c1 -->|issued| c0") || !strings.Contains(r.Mermaid, "r0 -->|issued| c1") {
		t.Errorf("mermaid missing edges:\n%s", r.Mermaid)
	}
	wantKey(t, r, "trusted", "store", "trusted-link")
	// Colour-blind cues: states are named in words and differ by border.
	if !strings.Contains(r.Mermaid, "<br/>trusted path") || !strings.Contains(r.Mermaid, "<br/>trusted root") {
		t.Errorf("node states not named in words:\n%s", r.Mermaid)
	}
	if !strings.Contains(r.Mermaid, "classDef store fill:#e9f3ec,stroke:#2c6a3d,color:#16202b,stroke-width:3px,stroke-dasharray:6 4") {
		t.Errorf("store root not drawn thick and dashed:\n%s", r.Mermaid)
	}
}

// wantKey checks the diagram key lists exactly the styles in use, in order.
func wantKey(t *testing.T, r *Result, ids ...string) {
	t.Helper()
	var got []string
	for _, k := range r.DiagramKey {
		got = append(got, k.ID)
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Errorf("diagram key %v, want %v", got, ids)
	}
}

func TestOutOfOrder(t *testing.T) {
	root := testpki.Root("Root")
	i1 := testpki.Intermediate("Issuing CA 1", root)
	i2 := testpki.Intermediate("Issuing CA 2", i1)
	leaf := testpki.Leaf("www.example.test", i2)
	store := truststore.NewFromCerts(testpki.X509(root), "test")
	r := Analyze(testpki.X509(leaf, i1, i2), opts(store))
	wantStatus(t, r, "order", Fail)
	wantStatus(t, r, "mozilla_root", Pass)
	wantStatus(t, r, "extra_certs", Pass)
}

func TestExtraUnrelatedCA(t *testing.T) {
	p := newPKI()
	other := testpki.Root("Unrelated Root")
	r := Analyze(testpki.X509(p.leaf, p.inter, other), opts(p.store))
	wantStatus(t, r, "extra_certs", Fail)
	wantStatus(t, r, "order", Pass)
	if r.Chain[2].Extraneous != "unrelated" {
		t.Errorf("extraneous = %q", r.Chain[2].Extraneous)
	}
}

// Unrelated certificates that chain to each other are drawn linked, even
// though no path from the leaf reaches them.
func TestUnrelatedChainLinked(t *testing.T) {
	p := newPKI()
	otherRoot := testpki.Root("Other Root")
	otherInter := testpki.Intermediate("Other Intermediate", otherRoot)
	r := Analyze(testpki.X509(p.leaf, p.inter, otherInter, otherRoot), opts(p.store))
	for _, i := range []int{2, 3} {
		if r.Chain[i].Extraneous != "unrelated" {
			t.Errorf("chain[%d] extraneous = %q", i, r.Chain[i].Extraneous)
		}
	}
	for _, k := range r.DiagramKey {
		if k.ID == "unrelated" && (!k.Hatch || k.Class != "bad") {
			t.Errorf("unrelated key entry not hatched: %+v", k)
		}
	}
	if !strings.Contains(r.Mermaid, "c3 -->|issued| c2") {
		t.Errorf("unrelated pair not linked:\n%s", r.Mermaid)
	}
	for _, bad := range []string{"c2 -->|issued| c3", "c2 -->|issued| c1", "c3 -->|issued| c1"} {
		if strings.Contains(r.Mermaid, bad) {
			t.Errorf("spurious link %q:\n%s", bad, r.Mermaid)
		}
	}
}

func TestDuplicate(t *testing.T) {
	p := newPKI()
	r := Analyze(testpki.X509(p.leaf, p.inter, p.inter), opts(p.store))
	wantStatus(t, r, "extra_certs", Warn)
	if r.Chain[2].Extraneous != "duplicate" || r.Chain[2].DuplicateOf != 1 {
		t.Errorf("dup: %+v", r.Chain[2])
	}
}

func TestExpiredIntermediate(t *testing.T) {
	root := testpki.Root("Root")
	inter := testpki.Intermediate("Old Intermediate", root, testpki.Opts{
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	leaf := testpki.Leaf("www.example.test", inter)
	store := truststore.NewFromCerts(testpki.X509(root), "test")
	r := Analyze(testpki.X509(leaf, inter), opts(store))
	wantStatus(t, r, "validity", Fail)
	if r.Chain[1].Status != StatusExpired {
		t.Errorf("status %s", r.Chain[1].Status)
	}
	if r.Paths[0].TimeValid {
		t.Error("path should not be time-valid")
	}
}

func TestExpiringSoon(t *testing.T) {
	p := newPKI()
	leaf := testpki.Leaf("www.example.test", p.inter, testpki.Opts{NotAfter: time.Now().Add(5 * 24 * time.Hour)})
	r := Analyze(testpki.X509(leaf, p.inter), opts(p.store))
	wantStatus(t, r, "validity", Warn)
}

func TestRootSent(t *testing.T) {
	p := newPKI()
	r := Analyze(testpki.X509(p.leaf, p.inter, p.root), opts(p.store))
	wantStatus(t, r, "root_sent", Info)
	wantStatus(t, r, "extra_certs", Pass)
	wantStatus(t, r, "order", Pass)
	if len(r.StoreRoots) != 0 {
		t.Errorf("root was sent; store roots should be empty, got %d", len(r.StoreRoots))
	}
}

func TestIncompleteChain(t *testing.T) {
	p := newPKI()
	r := Analyze(testpki.X509(p.leaf), opts(p.store))
	wantStatus(t, r, "mozilla_root", Fail)
	if r.Paths[0].Terminal != TermIncomplete || !strings.Contains(r.Paths[0].MissingIssuer, "Test Intermediate") {
		t.Errorf("path %+v", r.Paths[0])
	}
	if !strings.Contains(r.Mermaid, "Missing issuer") {
		t.Error("mermaid should show missing issuer")
	}
	wantKey(t, r, "other", "missing", "missing-link")
}

func TestUntrustedRoot(t *testing.T) {
	p := newPKI()
	r := Analyze(testpki.X509(p.leaf, p.inter, p.root), opts(truststore.NewFromCerts(nil, "empty")))
	wantStatus(t, r, "mozilla_root", Fail)
	if r.Paths[0].Terminal != TermUntrustedRoot {
		t.Errorf("terminal %s", r.Paths[0].Terminal)
	}
}

// Cross-signed: new root's key also certified by an old root. The server sends
// leaf, inter, newRoot(cross-signed by old). Two paths: via store newRoot and
// via the cross-sign to oldRoot.
func TestCrossSignTwoPaths(t *testing.T) {
	oldRoot := testpki.Root("Old Root")
	newRoot := testpki.Root("New Root")
	cross := testpki.Intermediate("New Root", oldRoot, testpki.Opts{Key: newRoot.Key})
	inter := testpki.Intermediate("Issuing CA", newRoot)
	leaf := testpki.Leaf("www.example.test", inter)

	// Both roots trusted → two trusted paths, cross cert used, nothing extraneous.
	both := truststore.NewFromCerts(testpki.X509(oldRoot, newRoot), "test")
	r := Analyze(testpki.X509(leaf, inter, cross), opts(both))
	if n := countTrusted(r.Paths); n != 2 {
		t.Fatalf("trusted paths = %d, want 2: %+v", n, r.Paths)
	}
	if !r.Paths[0].Best || len(r.Paths[0].Nodes) != 3 {
		t.Errorf("best path should be the short one: %+v", r.Paths[0])
	}
	wantStatus(t, r, "extra_certs", Pass)

	// Only new root trusted → cross-sign is on an alternate (untrusted) path.
	only := truststore.NewFromCerts(testpki.X509(newRoot), "test")
	r = Analyze(testpki.X509(leaf, inter, cross), opts(only))
	wantStatus(t, r, "extra_certs", Warn)
	if r.Chain[2].Extraneous != "alternate_path" {
		t.Errorf("cross extraneous = %q", r.Chain[2].Extraneous)
	}
}

func TestPendingDistrust(t *testing.T) {
	p := newPKI()
	o := opts(p.store)
	o.Pending = map[string]config.PendingDistrust{
		truststore.FingerprintSHA256(p.root.Cert): {Date: "2027-01-01", Note: "test"},
	}
	r := Analyze(testpki.X509(p.leaf, p.inter), o)
	wantStatus(t, r, "pending_distrust", Warn)
	if !r.Paths[0].Pending || r.StoreRoots[0].PendingDistrust == nil {
		t.Error("pending not propagated")
	}
	if !strings.Contains(r.Mermaid, "<b>pending distrust</b>") {
		t.Error("mermaid should label pending distrust")
	}
}

// Arrows on a path through a pending-distrust CA are amber and dotted, not
// the trusted style.
func TestPendingDistrustLinks(t *testing.T) {
	p := newPKI()
	o := opts(p.store)
	o.Pending = map[string]config.PendingDistrust{
		truststore.FingerprintSHA256(p.inter.Cert): {Date: "2027-01-01"},
	}
	r := Analyze(testpki.X509(p.leaf, p.inter), o)
	wantKey(t, r, "trusted", "store", "pending", "pending-link")
	if !strings.Contains(r.Mermaid, "linkStyle 0 stroke:#8a5a00,stroke-width:2px,stroke-dasharray:2 3") {
		t.Errorf("pending link not styled:\n%s", r.Mermaid)
	}
}

// Arrows on a path to a root no store includes are red and dash-dotted.
func TestUntrustedRootLinks(t *testing.T) {
	p := newPKI()
	empty := storeWith(nil, nil)
	r := Analyze(testpki.X509(p.leaf, p.inter, p.root), opts(empty))
	if len(r.Paths) != 1 || r.Paths[0].Terminal != TermUntrustedRoot {
		t.Fatalf("paths: %+v", r.Paths)
	}
	wantKey(t, r, "other", "untrusted-link")
	if !strings.Contains(r.Mermaid, "stroke:#b3261e,stroke-width:2px,stroke-dasharray:8 3 2 3") {
		t.Errorf("untrusted link not styled:\n%s", r.Mermaid)
	}
}

// A root that stores trust only for older certificates counts as untrusted
// for the arrows.
func TestLimitedRootLinks(t *testing.T) {
	p := newPKI()
	s := storeWith([]*testpki.Cert{p.root}, map[string]string{truststore.Microsoft: truststore.Limited})
	r := Analyze(testpki.X509(p.leaf, p.inter), opts(s))
	if len(r.Paths) != 1 || len(r.Paths[0].Stores) != 0 || len(r.Paths[0].LimitedStores) != 1 {
		t.Fatalf("paths: %+v", r.Paths)
	}
	for _, k := range r.DiagramKey {
		if k.ID == "trusted-link" {
			t.Errorf("limited-only path drawn as trusted:\n%s", r.Mermaid)
		}
	}
	if !strings.Contains(r.Mermaid, "stroke:#b3261e") {
		t.Errorf("limited-only path not drawn as untrusted:\n%s", r.Mermaid)
	}
}

func TestHostnameMismatch(t *testing.T) {
	p := newPKI()
	o := opts(p.store)
	o.Host = "other.example.test"
	r := Analyze(testpki.X509(p.leaf, p.inter), o)
	wantStatus(t, r, "hostname", Fail)
}

func TestMermaidEscape(t *testing.T) {
	got := mermaidEscape(`a"b<c>[d]`)
	if strings.ContainsAny(got, `"<>[]`) {
		t.Errorf("unescaped: %s", got)
	}
	// Mermaid's label markdown must not see links, lists or headings.
	for _, in := range []string{"www.washington.edu", "https://example.com", "ca@example.com", "1. Root", "# Root"} {
		got := mermaidEscape(in)
		if !strings.HasPrefix(got, wordJoiner) {
			t.Errorf("%q: no leading word joiner: %q", in, got)
		}
		for _, bad := range []string{"www.", "s://", "a@e", "1."} {
			if strings.Contains(got, bad) {
				t.Errorf("%q: %q survives escaping: %q", in, bad, got)
			}
		}
		if strings.ReplaceAll(got, wordJoiner, "") != in {
			t.Errorf("%q: visible text changed: %q", in, got)
		}
	}
}

func storeWith(certs []*testpki.Cert, trust map[string]string) *truststore.Store {
	m := map[string]map[string]string{}
	xs := testpki.X509(certs...)
	for _, c := range xs {
		m[truststore.FingerprintSHA256(c)] = trust
	}
	return truststore.NewWithTrust(xs, m, "test")
}

func TestTrustStoresSomeMissing(t *testing.T) {
	p := newPKI()
	s := storeWith([]*testpki.Cert{p.root}, map[string]string{truststore.Microsoft: truststore.Trusted, truststore.Mozilla: truststore.Trusted})
	r := Analyze(testpki.X509(p.leaf, p.inter), opts(s))
	c := check(t, r, "mozilla_root")
	if c.Status != Warn || !strings.Contains(strings.Join(c.Items, "|"), "Apple: no trusted path") {
		t.Fatalf("got %s %q %v", c.Status, c.Detail, c.Items)
	}
	if r.TrustStores[2].Status != truststore.Trusted || r.TrustStores[0].Status != "untrusted" {
		t.Errorf("trustStores = %+v", r.TrustStores)
	}
	// Only requiring the stores that trust it passes.
	o := opts(s)
	o.RequiredStores = []string{truststore.Microsoft, truststore.Mozilla}
	wantStatus(t, Analyze(testpki.X509(p.leaf, p.inter), o), "mozilla_root", Pass)
}

func TestTrustStoresLimitedOnly(t *testing.T) {
	p := newPKI()
	s := storeWith([]*testpki.Cert{p.root}, map[string]string{truststore.Microsoft: truststore.Limited})
	r := Analyze(testpki.X509(p.leaf, p.inter), opts(s))
	wantStatus(t, r, "mozilla_root", Fail)
	if r.Paths[0].Terminal != TermUntrustedRoot || len(r.Paths[0].LimitedStores) != 1 {
		t.Errorf("path = %+v", r.Paths[0])
	}
}

// A cross-sign lets each store find its own root: the check passes when the
// union of paths covers every store.
func TestTrustStoresSplitAcrossCrossSign(t *testing.T) {
	oldRoot := testpki.Root("Old Root")
	newRoot := testpki.Root("New Root")
	cross := testpki.Intermediate("New Root", oldRoot, testpki.Opts{Key: newRoot.Key})
	inter := testpki.Intermediate("Issuing CA", newRoot)
	leaf := testpki.Leaf("www.example.test", inter)
	m := map[string]map[string]string{
		truststore.FingerprintSHA256(oldRoot.Cert): {truststore.Microsoft: truststore.Trusted},
		truststore.FingerprintSHA256(newRoot.Cert): {truststore.Apple: truststore.Trusted, truststore.Chrome: truststore.Trusted, truststore.Mozilla: truststore.Trusted},
	}
	s := truststore.NewWithTrust(testpki.X509(oldRoot, newRoot), m, "test")
	r := Analyze(testpki.X509(leaf, inter, cross), opts(s))
	wantStatus(t, r, "mozilla_root", Pass)
	wantStatus(t, r, "extra_certs", Pass)
	if best := r.Paths[0]; !best.Best || len(best.Stores) != 3 {
		t.Errorf("best path should be the 3-store one: %+v", best)
	}
}
