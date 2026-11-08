// Package analyze inspects a presented certificate chain: ordering, validity
// periods, extraneous certificates, Mozilla root trust, pending distrust, and
// every possible issuance path (including cross-signs).
package analyze

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/truststore"
)

// Check statuses, ordered by severity.
const (
	Pass = "pass"
	Info = "info"
	Warn = "warn"
	Fail = "fail"
)

var severity = map[string]int{Pass: 0, Info: 1, Warn: 2, Fail: 3}

// Worst returns the more severe of two statuses.
func Worst(a, b string) string {
	if severity[b] > severity[a] {
		return b
	}
	return a
}

// Path terminal states.
const (
	TermMozillaRoot   = "mozilla_root"
	TermUntrustedRoot = "untrusted_root"
	TermIncomplete    = "incomplete"
)

const (
	maxDepth = 8
	maxPaths = 32
)

// Options control analysis.
type Options struct {
	Host         string
	Now          time.Time
	ExpiringSoon time.Duration
	Store        *truststore.Store
	Pending      map[string]config.PendingDistrust
	// Revocation, when set, is called for each certificate on the best path
	// with its issuer, concurrently. It must be safe for concurrent use.
	Revocation func(cert, issuer *x509.Certificate) *Revocation
	// RequiredStores are the root programs that must all trust a path for
	// the trust check to pass. Empty means all of them.
	RequiredStores []string
	// Staple is the OCSP response the server stapled, if any.
	Staple []byte
}

// Path is one issuance path from the leaf upward.
type Path struct {
	Nodes         []string `json:"nodes"` // CertInfo IDs, leaf first
	Terminal      string   `json:"terminal"`
	MissingIssuer string   `json:"missingIssuer,omitempty"` // for incomplete paths
	Trusted       bool     `json:"trusted"`                 // ends at a root at least one program trusts
	Stores        []string `json:"stores,omitempty"`        // programs that fully trust the end root
	LimitedStores []string `json:"limitedStores,omitempty"` // programs that trust it only for older certificates
	TimeValid     bool     `json:"timeValid"`               // every cert in validity window
	Pending       bool     `json:"pendingDistrust"`         // passes through a pending-distrust CA
	Best          bool     `json:"best"`
}

// Check is one summary card.
type Check struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Status string   `json:"status"`
	Detail string   `json:"detail"`
	Items  []string `json:"items,omitempty"`
}

// Result is the full analysis for one presented chain.
type Result struct {
	Chain      []CertInfo `json:"chain"`      // as presented, in order
	StoreRoots []CertInfo `json:"storeRoots"` // Mozilla roots used but not sent
	Paths      []Path     `json:"paths"`
	Checks     []Check    `json:"checks"`
	Overall    string     `json:"overall"`
	Mermaid    string     `json:"mermaid"`
	// DiagramKey lists, in display order, only the node and link styles the
	// diagram actually uses, with the colours it draws them in.
	DiagramKey []KeyEntry `json:"diagramKey"`
	// TrustStores says, for each root program, whether any path is trusted.
	TrustStores []StoreResult `json:"trustStores"`
}

// StoreResult is the outcome for one root program.
type StoreResult struct {
	Store    string `json:"store"`    // apple | chrome | microsoft | mozilla
	Label    string `json:"label"`    // display name
	Status   string `json:"status"`   // trusted | limited | untrusted
	Required bool   `json:"required"` // counts toward the trust check
}

type node struct {
	cert *x509.Certificate
	info *CertInfo
}

type analyzer struct {
	o        Options
	nodes    map[string]*node // by SHA-256
	ids      map[string]string
	order    []string // presented unique fingerprints in order
	store    []*CertInfo
	paths    []Path
	sigCache map[[2]string]bool
}

// Analyze runs every check against the presented chain.
func Analyze(presented []*x509.Certificate, o Options) *Result {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	a := &analyzer{o: o, nodes: map[string]*node{}, ids: map[string]string{}, sigCache: map[[2]string]bool{}}
	res := &Result{}

	firstIdx := map[string]int{}
	for i, c := range presented {
		fp := truststore.FingerprintSHA256(c)
		ci := describe(c, fmt.Sprintf("c%d", i), i, "presented", o)
		if j, dup := firstIdx[fp]; dup {
			ci.ID = res.Chain[j].ID
			ci.Extraneous = "duplicate"
			ci.DuplicateOf = j
			res.Chain = append(res.Chain, ci)
			continue
		}
		firstIdx[fp] = i
		res.Chain = append(res.Chain, ci)
		a.order = append(a.order, fp)
	}
	for _, fp := range a.order {
		ci := &res.Chain[firstIdx[fp]]
		a.nodes[fp] = &node{cert: presented[firstIdx[fp]], info: ci}
		a.ids[fp] = ci.ID
	}
	if len(presented) == 0 {
		res.Checks = []Check{{ID: "chain", Title: "Certificate chain", Status: Fail, Detail: "The server sent no certificates."}}
		res.Overall = Fail
		return res
	}

	a.walk([]string{a.order[0]}, map[string]bool{a.order[0]: true})
	a.scorePaths()
	res.Paths = a.paths
	a.markUsage(res)
	a.checkRevocation()
	res.TrustStores = a.storeResults()
	res.Checks = a.checks(res)
	for _, c := range res.Checks {
		res.Overall = Worst(res.Overall, c.Status)
	}
	if res.Overall == "" {
		res.Overall = Pass
	}
	res.Mermaid, res.DiagramKey = a.mermaid(res)
	return res
}

func (a *analyzer) verifies(child, parent *x509.Certificate) bool {
	k := [2]string{truststore.FingerprintSHA256(child), truststore.FingerprintSHA256(parent)}
	if v, ok := a.sigCache[k]; ok {
		return v
	}
	v := string(child.RawIssuer) == string(parent.RawSubject) &&
		parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
	a.sigCache[k] = v
	return v
}

// issuers returns fingerprints of certs (presented first, then store roots)
// that verifiably signed fp.
func (a *analyzer) issuers(fp string) []string {
	child := a.nodes[fp].cert
	var out []string
	for _, cand := range a.order {
		if cand != fp && a.verifies(child, a.nodes[cand].cert) {
			out = append(out, cand)
		}
	}
	if a.o.Store == nil {
		return out
	}
	for _, r := range a.o.Store.CandidateIssuers(child) {
		rfp := truststore.FingerprintSHA256(r)
		if rfp == fp || contains(out, rfp) || !a.verifies(child, r) {
			continue
		}
		if _, known := a.nodes[rfp]; !known {
			ci := describe(r, fmt.Sprintf("r%d", len(a.store)), -1, "mozilla_store", a.o)
			a.store = append(a.store, &ci)
			a.nodes[rfp] = &node{cert: r, info: &ci}
			a.ids[rfp] = ci.ID
		}
		out = append(out, rfp)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (a *analyzer) emit(p Path) {
	if len(a.paths) < maxPaths {
		a.paths = append(a.paths, p)
	}
}

func (a *analyzer) walk(chain []string, seen map[string]bool) {
	if len(a.paths) >= maxPaths {
		return
	}
	fp := chain[len(chain)-1]
	n := a.nodes[fp]
	ids := func() []string {
		out := make([]string, len(chain))
		for i, f := range chain {
			out[i] = a.ids[f]
		}
		return out
	}
	if n.info.InMozilla {
		a.emit(Path{Nodes: ids(), Terminal: TermMozillaRoot})
		return
	}
	if n.info.SelfSigned {
		a.emit(Path{Nodes: ids(), Terminal: TermUntrustedRoot})
		return
	}
	if len(chain) >= maxDepth {
		a.emit(Path{Nodes: ids(), Terminal: TermIncomplete, MissingIssuer: n.info.Issuer + " (max depth reached)"})
		return
	}
	extended := false
	for _, iss := range a.issuers(fp) {
		if seen[iss] {
			continue
		}
		extended = true
		seen[iss] = true
		a.walk(append(append([]string{}, chain...), iss), seen)
		delete(seen, iss)
	}
	if !extended {
		a.emit(Path{Nodes: ids(), Terminal: TermIncomplete, MissingIssuer: n.info.Issuer})
	}
}

func (a *analyzer) info(id string) *CertInfo {
	for _, n := range a.nodes {
		if n.info.ID == id {
			return n.info
		}
	}
	return nil
}

func timeOK(s string) bool { return s == StatusValid || s == StatusExpiringSoon }

func (a *analyzer) scorePaths() {
	for i := range a.paths {
		p := &a.paths[i]
		p.Trusted = p.Terminal == TermMozillaRoot
		if end := a.info(p.Nodes[len(p.Nodes)-1]); p.Terminal != TermIncomplete && end != nil {
			for st, lvl := range end.Stores {
				if lvl == truststore.Trusted {
					p.Stores = append(p.Stores, st)
				} else {
					p.LimitedStores = append(p.LimitedStores, st)
				}
			}
			truststore.SortStores(p.Stores)
			truststore.SortStores(p.LimitedStores)
		}
		p.TimeValid = true
		for _, id := range p.Nodes {
			ci := a.info(id)
			if !timeOK(ci.Status) {
				p.TimeValid = false
			}
			if ci.PendingDistrust != nil {
				p.Pending = true
			}
		}
	}
	// Best path: trusted, time-valid, not pending, shortest; stable by discovery.
	required := a.required()
	score := func(p Path) int {
		s := 0
		for _, st := range p.Stores {
			if contains(required, st) {
				s += 16
			}
		}
		if p.Trusted {
			s += 8
		}
		if p.TimeValid {
			s += 4
		}
		if !p.Pending {
			s += 2
		}
		return s
	}
	best := -1
	for i, p := range a.paths {
		if best < 0 || score(p) > score(a.paths[best]) ||
			(score(p) == score(a.paths[best]) && len(p.Nodes) < len(a.paths[best].Nodes)) {
			best = i
		}
	}
	if best >= 0 {
		a.paths[best].Best = true
	}
	sort.SliceStable(a.paths, func(i, j int) bool {
		if a.paths[i].Best != a.paths[j].Best {
			return a.paths[i].Best
		}
		return score(a.paths[i]) > score(a.paths[j])
	})
}

func (a *analyzer) required() []string {
	if len(a.o.RequiredStores) > 0 {
		return a.o.RequiredStores
	}
	return truststore.AllStores
}

// storeResults works out, per root program, the best trust any path gets.
func (a *analyzer) storeResults() []StoreResult {
	req := a.required()
	var out []StoreResult
	for _, st := range truststore.AllStores {
		r := StoreResult{Store: st, Label: truststore.Label(st), Status: "untrusted", Required: contains(req, st)}
		for _, p := range a.paths {
			if contains(p.Stores, st) {
				r.Status = truststore.Trusted
				break
			}
			if contains(p.LimitedStores, st) {
				r.Status = truststore.Limited
			}
		}
		out = append(out, r)
	}
	return out
}

func (a *analyzer) bestPath() *Path {
	for i := range a.paths {
		if a.paths[i].Best {
			return &a.paths[i]
		}
	}
	return nil
}

// markUsage sets OnTrustedPath and Extraneous on presented certs.
func (a *analyzer) markUsage(res *Result) {
	onTrusted, onAny := map[string]bool{}, map[string]bool{}
	for _, p := range a.paths {
		for _, id := range p.Nodes {
			onAny[id] = true
			if p.Trusted {
				onTrusted[id] = true
			}
		}
	}
	anyTrusted := len(onTrusted) > 0
	mark := func(ci *CertInfo) {
		ci.OnTrustedPath = onTrusted[ci.ID]
		if ci.Index == 0 || ci.Extraneous == "duplicate" {
			return
		}
		switch {
		case anyTrusted && !onTrusted[ci.ID] && onAny[ci.ID]:
			ci.Extraneous = "alternate_path"
		case !onAny[ci.ID]:
			ci.Extraneous = "unrelated"
		}
	}
	for i := range res.Chain {
		mark(&res.Chain[i])
	}
	for _, s := range a.store {
		s.OnTrustedPath = onTrusted[s.ID]
	}
	res.StoreRoots = res.StoreRoots[:0]
	for _, s := range a.store {
		res.StoreRoots = append(res.StoreRoots, *s)
	}
}

func label(ci CertInfo) string {
	if ci.Index >= 0 {
		return fmt.Sprintf("#%d %s", ci.Index, ci.SubjectCN)
	}
	return ci.SubjectCN + " (trust store)"
}

func (a *analyzer) checks(res *Result) []Check {
	var out []Check
	best := a.bestPath()
	leaf := res.Chain[0]

	// 1. Trusted root
	{
		c := Check{ID: "mozilla_root", Title: "Chains to a trusted root"}
		var trusted []string
		terms := map[string]int{}
		for _, p := range a.paths {
			terms[p.Terminal]++
			if p.Trusted {
				last := a.info(p.Nodes[len(p.Nodes)-1])
				trusted = appendUnique(trusted, last.SubjectCN)
			}
		}
		var ok, short []string
		for _, sr := range res.TrustStores {
			if !sr.Required {
				continue
			}
			switch sr.Status {
			case truststore.Trusted:
				ok = append(ok, sr.Label)
			case truststore.Limited:
				short = append(short, sr.Label+": limited, only for certificates issued before a cutoff date")
			default:
				short = append(short, sr.Label+": no trusted path")
			}
		}
		if len(trusted) > 0 && len(short) == 0 {
			c.Status = Pass
			c.Detail = fmt.Sprintf("Trusted by %s. %d of %d path(s) end at a trusted root.", joinAnd(ok), countTrusted(a.paths), len(a.paths))
			c.Items = trusted
		} else if len(trusted) > 0 {
			c.Status = Warn
			if len(ok) > 0 {
				c.Detail = fmt.Sprintf("Trusted by %s, but not by every trust store checked.", joinAnd(ok))
			} else {
				c.Detail = "The chain reaches a trusted root, but not one in the trust stores this server requires."
			}
			c.Items = short
		} else {
			c.Status = Fail
			switch {
			case terms[TermUntrustedRoot] > 0:
				c.Detail = "The chain ends at a self-signed root that is not in the trust store."
			default:
				c.Detail = "The chain stops before it reaches a root. The server is probably missing an intermediate certificate."
			}
			for _, p := range a.paths {
				if p.MissingIssuer != "" {
					c.Items = appendUnique(c.Items, "Missing issuer: "+p.MissingIssuer)
				}
			}
		}
		out = append(out, c)
	}

	// 2. Order
	{
		c := Check{ID: "order", Title: "Certificates in correct order"}
		if leaf.IsCA {
			c.Status = Warn
			c.Detail = "The first certificate is a CA certificate. The server must send its own (leaf) certificate first."
		}
		if best != nil {
			// The presented certs on the best path must appear at the front, in path order.
			var want []string
			for _, id := range best.Nodes {
				if ci := a.info(id); ci.Index >= 0 {
					want = append(want, id)
				}
			}
			var got []string
			for _, ci := range res.Chain {
				if ci.Extraneous == "" {
					got = append(got, ci.ID)
				}
			}
			ok := len(got) >= len(want)
			for i := 0; ok && i < len(want); i++ {
				if got[i] != want[i] {
					ok = false
				}
			}
			// And each presented cert on the path must sit immediately before its issuer in the raw chain.
			pos := map[string]int{}
			for _, ci := range res.Chain {
				if _, seen := pos[ci.ID]; !seen {
					pos[ci.ID] = ci.Index
				}
			}
			for i := 0; ok && i+1 < len(want); i++ {
				if pos[want[i+1]] != pos[want[i]]+1 {
					ok = false
				}
			}
			if ok && c.Status == "" {
				c.Status = Pass
				c.Detail = "Each certificate is immediately followed by its issuer."
			} else if !ok {
				c.Status = Fail
				c.Detail = "The certificates are out of order. Correct order:"
				for _, id := range want {
					ci := a.info(id)
					c.Items = append(c.Items, fmt.Sprintf("%s (currently position #%d)", ci.SubjectCN, ci.Index))
				}
			}
		}
		out = append(out, c)
	}

	// 3. Validity
	{
		c := Check{ID: "validity", Title: "Certificates within validity period", Status: Pass}
		scope := map[string]bool{}
		if best != nil {
			for _, id := range best.Nodes {
				scope[id] = true
			}
		}
		all := append(append([]CertInfo{}, res.Chain...), res.StoreRoots...)
		seen := map[string]bool{}
		for _, ci := range all {
			if seen[ci.ID] {
				continue
			}
			seen[ci.ID] = true
			critical := scope[ci.ID] || ci.Index == 0
			switch ci.Status {
			case StatusExpired, StatusNotYetValid:
				word := "expired " + ci.NotAfter.Format("2006-01-02")
				if ci.Status == StatusNotYetValid {
					word = "not valid until " + ci.NotBefore.Format("2006-01-02")
				}
				if critical {
					c.Status = Worst(c.Status, Fail)
					c.Items = append(c.Items, fmt.Sprintf("%s: %s", label(ci), word))
				} else {
					c.Status = Worst(c.Status, Warn)
					c.Items = append(c.Items, fmt.Sprintf("%s: %s (not on the best path)", label(ci), word))
				}
			case StatusExpiringSoon:
				c.Status = Worst(c.Status, Warn)
				c.Items = append(c.Items, fmt.Sprintf("%s: expires in %d day(s) (%s)", label(ci), ci.DaysRemaining, ci.NotAfter.Format("2006-01-02")))
			}
		}
		switch c.Status {
		case Pass:
			c.Detail = "Every certificate is currently valid."
		case Warn:
			c.Detail = "Some certificates expire soon, or are out of date but not on the best path."
		case Fail:
			c.Detail = "A certificate needed by the chain is expired or not yet valid."
		}
		out = append(out, c)
	}

	// 4. Extra CAs
	{
		c := Check{ID: "extra_certs", Title: "No unnecessary certificates", Status: Pass, Detail: "Every certificate sent is on the trusted path."}
		if countTrusted(a.paths) == 0 {
			c.Detail = "Every certificate sent is on the leaf's path."
		}
		for _, ci := range res.Chain {
			switch ci.Extraneous {
			case "unrelated":
				c.Status = Worst(c.Status, Fail)
				c.Items = append(c.Items, fmt.Sprintf("%s: not on the leaf's path", label(ci)))
			case "duplicate":
				c.Status = Worst(c.Status, Warn)
				c.Items = append(c.Items, fmt.Sprintf("%s: duplicate of position #%d", label(ci), ci.DuplicateOf))
			case "alternate_path":
				c.Status = Worst(c.Status, Warn)
				c.Items = append(c.Items, fmt.Sprintf("%s: only on a path that doesn't reach the trust store (maybe a cross-sign for older clients)", label(ci)))
			}
		}
		if c.Status != Pass {
			c.Detail = "The server sends certificates that aren't needed to reach a trusted root."
		}
		out = append(out, c)
	}

	// 5. Root sent
	for _, ci := range res.Chain {
		if ci.Index > 0 && ci.SelfSigned && ci.Extraneous == "" {
			out = append(out, Check{ID: "root_sent", Title: "Root certificate sent", Status: Info,
				Detail: "The server sends its root. Clients only trust roots they already have, so sending it adds bytes to the handshake without helping.",
				Items:  []string{label(ci)}})
			break
		}
	}

	// 6. Pending distrust
	{
		c := Check{ID: "pending_distrust", Title: "No CAs pending loss of trust", Status: Pass, Detail: "No certificate on a trusted path is scheduled to lose trust."}
		trustedPaths, pendingPaths := 0, 0
		flagged := map[string]bool{}
		for _, p := range a.paths {
			if !p.Trusted {
				continue
			}
			trustedPaths++
			if p.Pending {
				pendingPaths++
			}
			for _, id := range p.Nodes {
				ci := a.info(id)
				if ci.PendingDistrust != nil && !flagged[id] {
					flagged[id] = true
					item := label(*ci)
					if ci.PendingDistrust.Date != "" {
						item += ": distrust " + ci.PendingDistrust.Date
					}
					if ci.PendingDistrust.Note != "" {
						item += " (" + ci.PendingDistrust.Note + ")"
					}
					c.Items = append(c.Items, item)
				}
			}
		}
		if pendingPaths > 0 {
			c.Status = Warn
			if pendingPaths == trustedPaths {
				c.Detail = "Every trusted path goes through a CA that is scheduled to lose trust. Switch to a certificate from a different CA."
			} else {
				c.Detail = fmt.Sprintf("%d of %d trusted path(s) go through a CA scheduled to lose trust. The other paths are fine.", pendingPaths, trustedPaths)
			}
		}
		out = append(out, c)
	}

	// 7. Revocation
	if a.o.Revocation != nil {
		out = append(out, a.revocationCheck(res))
	}

	// 8. Hostname
	if a.o.Host != "" {
		c := Check{ID: "hostname", Title: "Leaf certificate matches hostname"}
		leafCert := a.nodes[a.order[0]].cert
		if err := leafCert.VerifyHostname(a.o.Host); err != nil {
			c.Status = Fail
			c.Detail = err.Error()
		} else {
			c.Status = Pass
			c.Detail = fmt.Sprintf("%q is covered by the leaf certificate.", a.o.Host)
		}
		out = append(out, c)
	}
	return out
}

// checkRevocation asks the issuer about every certificate on the best path
// that has a known issuer. Roots are skipped: nothing above them can revoke.
func (a *analyzer) checkRevocation() {
	if a.o.Revocation == nil {
		return
	}
	best := a.bestPath()
	if best == nil {
		return
	}
	fpOf := map[string]string{}
	for fp, id := range a.ids {
		fpOf[id] = fp
	}
	var wg sync.WaitGroup
	for i := 0; i+1 < len(best.Nodes); i++ {
		child, issuer := a.nodes[fpOf[best.Nodes[i]]], a.nodes[fpOf[best.Nodes[i+1]]]
		if child == nil || issuer == nil || child.info.SelfSigned {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			child.info.Revocation = a.o.Revocation(child.cert, issuer.cert)
		}()
	}
	wg.Wait()
}

func (a *analyzer) revocationCheck(res *Result) Check {
	c := Check{ID: "revocation", Title: "Certificates not revoked", Status: Pass}
	checked, problems := 0, 0
	for _, ci := range res.Chain {
		r := ci.Revocation
		if r == nil || ci.Extraneous == "duplicate" {
			continue
		}
		checked++
		if s := r.Revoked(); s != nil {
			c.Status = Fail
			item := fmt.Sprintf("%s: revoked", label(ci))
			if s.RevokedAt != nil {
				item += " on " + s.RevokedAt.UTC().Format("2006-01-02")
			}
			if s.Reason != "" {
				item += " (" + s.Reason + ")"
			}
			c.Items = append(c.Items, item+", says "+sourceName(r, s))
			continue
		}
		var notes []string
		for _, s := range []struct {
			name string
			src  *RevocationSource
		}{{"OCSP", r.OCSP}, {"CRL", r.CRL}} {
			switch {
			case s.src == nil:
			case s.src.Status == RevError:
				notes = append(notes, s.name+" could not be checked ("+s.src.Error+")")
			case s.src.Status == RevUnknown:
				notes = append(notes, s.name+" responder does not know this certificate")
			}
		}
		if r.OCSP == nil && r.CRL == nil {
			notes = append(notes, "names no OCSP responder or CRL")
		}
		good := (r.OCSP != nil && r.OCSP.Status == RevGood) || (r.CRL != nil && r.CRL.Status == RevGood)
		if len(notes) > 0 && !good {
			problems++
			c.Items = append(c.Items, label(ci)+": "+strings.Join(notes, "; "))
		}
	}
	switch {
	case checked == 0:
		c.Status, c.Detail = Info, "No certificate on the best path could be checked."
	case c.Status == Fail:
		c.Detail = "The issuer says a certificate on the best path is revoked. Clients that check will reject it."
	case problems > 0:
		c.Status, c.Detail = Info, "Some certificates could not be checked for revocation. None was found revoked."
	default:
		c.Detail = "Every certificate on the best path was checked with its issuer's OCSP responder or CRL, and none is revoked."
	}
	return c
}

func sourceName(r *Revocation, s *RevocationSource) string {
	if s == r.OCSP {
		return "OCSP"
	}
	return "the CRL"
}

func countTrusted(ps []Path) int {
	n := 0
	for _, p := range ps {
		if p.Trusted {
			n++
		}
	}
	return n
}

func appendUnique(s []string, v string) []string {
	if contains(s, v) {
		return s
	}
	return append(s, v)
}

// wordJoiner (U+2060) is invisible and never a line-break point.
const wordJoiner = "\u2060"

// mermaidEscape makes a string safe inside a quoted Mermaid label.
//
// Mermaid runs label text through a markdown parser that supports only bold
// and italics; anything else renders as "Unsupported markdown: link" (or
// list, heading) instead of the text. Certificate names often look like
// markdown: "www.example.com" and "a@b.c" autolink, "1. Root" is a list item
// and "# Root" a heading. A word joiner before the start and before every
// ".", "@" and ":" breaks those patterns without changing what is shown.
func mermaidEscape(s string) string {
	r := strings.NewReplacer(`"`, "#quot;", "<", "#lt;", ">", "#gt;", "&", "#amp;", "`", "#96;", "\n", " ", "|", "#124;", "[", "#91;", "]", "#93;", "{", "#123;", "}", "#125;",
		".", wordJoiner+".", "@", wordJoiner+"@", ":", wordJoiner+":")
	return wordJoiner + r.Replace(s)
}

// KeyEntry describes one style in the paths diagram so the UI can draw a
// key that matches it exactly.
type KeyEntry struct {
	ID     string  `json:"id"`   // e.g. "trusted", "missing", "trusted-link"
	Kind   string  `json:"kind"` // "node" or "link"
	Fill   string  `json:"fill,omitempty"`
	Stroke string  `json:"stroke"`
	Text   string  `json:"text,omitempty"`
	Width  float64 `json:"width"`
	Dash   string  `json:"dash,omitempty"`  // SVG stroke-dasharray; empty is solid
	Hatch  bool    `json:"hatch,omitempty"` // diagonal stripes over the fill
	Class  string  `json:"class,omitempty"` // Mermaid class the node style uses
}

// diagramStyles is the single source of the diagram's colours. Each key
// entry names the Mermaid class it is drawn with; several entries can share
// a class (for example expired and unrelated certificates).
var diagramStyles = []struct {
	KeyEntry
	class string
}{
	// Every state differs by more than colour, for colour-blind readers:
	// trusted nodes have a thick border (dashed when not sent), warnings a
	// dotted border, problems are hatched, and each node also says its state
	// in words. Trusted links are thick; links to a missing issuer dashed.
	{KeyEntry{ID: "trusted", Kind: "node", Fill: "#e9f3ec", Stroke: "#2c6a3d", Text: "#16202b", Width: 3}, "trusted"},
	{KeyEntry{ID: "store", Kind: "node", Fill: "#e9f3ec", Stroke: "#2c6a3d", Text: "#16202b", Width: 3, Dash: "6 4"}, "store"},
	{KeyEntry{ID: "other", Kind: "node", Fill: "#f3f5f7", Stroke: "#7d8a99", Text: "#16202b", Width: 1.5}, "cert"},
	{KeyEntry{ID: "pending", Kind: "node", Fill: "#fbf3e0", Stroke: "#8a5a00", Text: "#16202b", Width: 2, Dash: "2 3"}, "warn"},
	{KeyEntry{ID: "alternate", Kind: "node", Fill: "#fbf3e0", Stroke: "#8a5a00", Text: "#16202b", Width: 2, Dash: "2 3"}, "warn"},
	{KeyEntry{ID: "revoked", Kind: "node", Fill: "#fbeceb", Stroke: "#b3261e", Text: "#16202b", Width: 1.5, Hatch: true}, "bad"},
	{KeyEntry{ID: "invalid", Kind: "node", Fill: "#fbeceb", Stroke: "#b3261e", Text: "#16202b", Width: 1.5, Hatch: true}, "bad"},
	{KeyEntry{ID: "unrelated", Kind: "node", Fill: "#fbeceb", Stroke: "#b3261e", Text: "#16202b", Width: 1.5, Hatch: true}, "bad"},
	{KeyEntry{ID: "missing", Kind: "node", Fill: "transparent", Stroke: "#b3261e", Text: "#b3261e", Width: 1.5, Dash: "6 4"}, "missing"},
	{KeyEntry{ID: "link", Kind: "link", Stroke: "#7d8a99", Width: 1.5}, ""},
	{KeyEntry{ID: "trusted-link", Kind: "link", Stroke: "#2c6a3d", Width: 3}, ""},
	{KeyEntry{ID: "missing-link", Kind: "link", Stroke: "#7d8a99", Width: 1.5, Dash: "3 3"}, ""},
}

func (a *analyzer) mermaid(res *Result) (string, []KeyEntry) {
	var b strings.Builder
	used := map[string]bool{}
	classOf := map[string]string{}
	for _, st := range diagramStyles {
		classOf[st.ID] = st.class
	}
	// Roots at the top, the leaf at the bottom: edges run issuer → subject.
	b.WriteString("flowchart TD\n")
	all := append([]CertInfo{}, res.Chain...)
	all = append(all, res.StoreRoots...)
	declared := map[string]bool{}
	var declaredIDs []string
	for _, ci := range all {
		if declared[ci.ID] || ci.Extraneous == "duplicate" {
			continue
		}
		declared[ci.ID] = true
		declaredIDs = append(declaredIDs, ci.ID)
		where := fmt.Sprintf("sent #%d", ci.Index)
		if ci.Index < 0 {
			where = "trust store (not sent)"
		}
		extra := ""
		switch {
		case ci.InMozilla:
			extra = "<br/>trusted root"
		case ci.SelfSigned:
			extra = "<br/>untrusted root"
		}
		if ci.PendingDistrust != nil {
			extra += "<br/>pending distrust"
		}
		if ci.Status == StatusExpired || ci.Status == StatusNotYetValid {
			extra += "<br/>" + strings.ReplaceAll(ci.Status, "_", " ")
		}
		if ci.Extraneous == "unrelated" {
			extra += "<br/>unrelated"
		}
		if ci.Revocation.Revoked() != nil {
			extra += "<br/>revoked"
		}
		key := "other"
		switch {
		case ci.Revocation.Revoked() != nil:
			key = "revoked"
		case ci.Status == StatusExpired || ci.Status == StatusNotYetValid:
			key = "invalid"
		case ci.Extraneous == "unrelated":
			key = "unrelated"
		case ci.PendingDistrust != nil:
			key = "pending"
		case ci.Extraneous == "alternate_path":
			key = "alternate"
		case ci.Index < 0:
			key = "store"
		case ci.OnTrustedPath:
			key = "trusted"
		}
		// Name the state in words when nothing above already does, so no
		// node depends on colour alone.
		if extra == "" {
			switch key {
			case "trusted":
				extra = "<br/>trusted path"
			case "alternate":
				extra = "<br/>not needed"
			case "other":
				extra = "<br/>not on a trusted path"
			}
		}
		fmt.Fprintf(&b, "  %s[\"%s<br/><small>%s · %s…</small>%s\"]\n",
			ci.ID, mermaidEscape(ci.SubjectCN), where, ci.SHA256[:12], extra)
		used[key] = true
		fmt.Fprintf(&b, "  class %s %s\n", ci.ID, classOf[key])
	}

	type edge struct{ from, to string }
	edges := map[edge]int{}
	var order []edge
	trustedEdge := map[edge]bool{}
	missing := 0
	for _, p := range a.paths {
		for i := 0; i+1 < len(p.Nodes); i++ {
			e := edge{p.Nodes[i], p.Nodes[i+1]}
			if _, ok := edges[e]; !ok {
				edges[e] = len(order)
				order = append(order, e)
			}
			if p.Trusted {
				trustedEdge[e] = true
			}
		}
		if p.Terminal == TermIncomplete {
			id := fmt.Sprintf("m%d", missing)
			missing++
			used["missing"] = true
			fmt.Fprintf(&b, "  %s[\"Missing issuer:<br/>%s\"]\n  class %s missing\n", id, mermaidEscape(p.MissingIssuer), id)
			e := edge{p.Nodes[len(p.Nodes)-1], id}
			edges[e] = len(order)
			order = append(order, e)
		}
	}
	// Paths only start at the leaf, so certificates that chain to each other
	// but not to the leaf (for example a leftover intermediate and its
	// cross-sign) would otherwise float unconnected. Link every drawn
	// certificate to every drawn certificate that verifiably signed it.
	fpOf := map[string]string{}
	for fp, id := range a.ids {
		fpOf[id] = fp
	}
	for _, child := range declaredIDs {
		for _, parent := range declaredIDs {
			e := edge{child, parent}
			if _, done := edges[e]; done || child == parent {
				continue
			}
			if a.verifies(a.nodes[fpOf[child]].cert, a.nodes[fpOf[parent]].cert) {
				edges[e] = len(order)
				order = append(order, e)
			}
		}
	}
	for _, e := range order {
		arrow := "-->"
		switch {
		case strings.HasPrefix(e.to, "m"):
			arrow = "-.->"
			used["missing-link"] = true
		case trustedEdge[e]:
			used["trusted-link"] = true
		default:
			used["link"] = true
		}
		fmt.Fprintf(&b, "  %s %s|issued| %s\n", e.to, arrow, e.from)
	}
	var key []KeyEntry
	classDone := map[string]bool{}
	for _, st := range diagramStyles {
		if st.ID == "trusted-link" {
			for i, e := range order {
				if trustedEdge[e] {
					fmt.Fprintf(&b, "  linkStyle %d stroke:%s,stroke-width:%gpx\n", i, st.Stroke, st.Width)
				}
			}
		}
		if st.class != "" && !classDone[st.class] {
			classDone[st.class] = true
			fmt.Fprintf(&b, "  classDef %s fill:%s,stroke:%s,color:%s,stroke-width:%gpx", st.class, st.Fill, st.Stroke, st.Text, st.Width)
			if st.Dash != "" {
				b.WriteString(",stroke-dasharray:" + st.Dash)
			}
			b.WriteString("\n")
		}
		if used[st.ID] {
			e := st.KeyEntry
			e.Class = st.class
			key = append(key, e)
		}
	}
	return b.String(), key
}

// joinAnd joins names as "A, B and C".
func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}
