// Package truststore keeps the set of publicly trusted roots and records
// which root programs (Apple, Chrome, Microsoft, Mozilla) include each one,
// using CCADB data.
package truststore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Root program IDs, in display order.
const (
	Apple     = "apple"
	Chrome    = "chrome"
	Microsoft = "microsoft"
	Mozilla   = "mozilla"
)

// AllStores lists every root program the store tracks.
var AllStores = []string{Apple, Chrome, Microsoft, Mozilla}

// Trust levels for one root in one program.
const (
	Trusted = "trusted"
	// Limited: Microsoft "NotBefore" roots, trusted only for certificates
	// issued before a cutoff date that CCADB's CSV does not publish.
	Limited = "limited"
)

// Store is a read-mostly, atomically swappable set of trusted roots.
type Store struct {
	mu        sync.RWMutex
	byFP      map[string]*x509.Certificate
	bySubject map[string][]*x509.Certificate
	bySKI     map[string][]*x509.Certificate
	trust     map[string]map[string]string // fingerprint -> program -> level
	// Cross-signs: certificates (from CCADB's intermediate report) that
	// give an included root's name and key a second issuer. crossAll is
	// the last downloaded candidate list; cross is the part of it that
	// matches the current roots.
	crossAll       []*x509.Certificate
	cross          []*x509.Certificate
	crossBySubject map[string][]*x509.Certificate
	crossBySKI     map[string][]*x509.Certificate
	source         string
	loadedAt       time.Time
	// Download status, set by the Loader.
	refreshFailing bool
	nextAttempt    time.Time
}

// Info describes the current store for display.
type Info struct {
	Source   string         `json:"source"`
	Count    int            `json:"count"`
	LoadedAt time.Time      `json:"loadedAt"`         // when the data was downloaded from CCADB
	Stores   map[string]int `json:"stores,omitempty"` // roots each program trusts fully
	// CrossSigns is how many cross-signs of included roots are known.
	CrossSigns int `json:"crossSigns,omitempty"`
	// RefreshFailing is set when the last download from CCADB failed;
	// NextAttempt is when the server tries again.
	RefreshFailing bool       `json:"refreshFailing,omitempty"`
	NextAttempt    *time.Time `json:"nextAttempt,omitempty"`
}

// FingerprintSHA256 returns the lowercase hex SHA-256 of the DER encoding.
func FingerprintSHA256(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// ParsePEMBundle parses every CERTIFICATE block, skipping unparsable ones.
func ParsePEMBundle(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return out
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			slog.Debug("skipping unparsable root", "err", err)
			continue
		}
		out = append(out, c)
	}
}

// NewFromCerts builds a store where every program trusts every given root
// (used by tests).
func NewFromCerts(certs []*x509.Certificate, source string) *Store {
	trust := map[string]map[string]string{}
	for _, c := range certs {
		m := map[string]string{}
		for _, st := range AllStores {
			m[st] = Trusted
		}
		trust[FingerprintSHA256(c)] = m
	}
	return NewWithTrust(certs, trust, source)
}

// Empty reports whether no roots are loaded, so trust cannot be checked.
func (s *Store) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byFP) == 0
}

func (s *Store) setStatus(failing bool, next time.Time) {
	s.mu.Lock()
	s.refreshFailing, s.nextAttempt = failing, next
	s.mu.Unlock()
}

// NewWithTrust builds a store from roots and their per-program trust.
// Roots no program trusts are dropped.
func NewWithTrust(certs []*x509.Certificate, trust map[string]map[string]string, source string) *Store {
	s := &Store{}
	s.set(certs, trust, source, time.Now())
	return s
}

func (s *Store) set(certs []*x509.Certificate, trust map[string]map[string]string, source string, loadedAt time.Time) {
	byFP := map[string]*x509.Certificate{}
	bySubj := map[string][]*x509.Certificate{}
	bySKI := map[string][]*x509.Certificate{}
	kept := map[string]map[string]string{}
	for _, c := range certs {
		fp := FingerprintSHA256(c)
		if _, dup := byFP[fp]; dup || len(trust[fp]) == 0 {
			continue
		}
		byFP[fp] = c
		kept[fp] = trust[fp]
		bySubj[string(c.RawSubject)] = append(bySubj[string(c.RawSubject)], c)
		if len(c.SubjectKeyId) > 0 {
			bySKI[string(c.SubjectKeyId)] = append(bySKI[string(c.SubjectKeyId)], c)
		}
	}
	s.mu.Lock()
	s.byFP, s.bySubject, s.bySKI, s.trust = byFP, bySubj, bySKI, kept
	s.source, s.loadedAt = source, loadedAt
	s.indexCrossLocked()
	s.mu.Unlock()
}

// SetCrossSigns replaces the cross-sign candidates. Only certificates that
// are not self-signed and carry the same subject and public key as an
// included root are kept, so a cross-sign can only stand in where that root
// already could: it never fills in an intermediate the server left out.
func (s *Store) SetCrossSigns(certs []*x509.Certificate) {
	s.mu.Lock()
	s.crossAll = certs
	s.indexCrossLocked()
	s.mu.Unlock()
}

func (s *Store) indexCrossLocked() {
	type key struct{ subj, spki string }
	roots := map[key]bool{}
	for _, r := range s.byFP {
		roots[key{string(r.RawSubject), string(r.RawSubjectPublicKeyInfo)}] = true
	}
	seen := map[string]bool{}
	s.cross = nil
	s.crossBySubject = map[string][]*x509.Certificate{}
	s.crossBySKI = map[string][]*x509.Certificate{}
	for _, c := range s.crossAll {
		fp := FingerprintSHA256(c)
		if seen[fp] || s.byFP[fp] != nil || bytes.Equal(c.RawIssuer, c.RawSubject) ||
			!roots[key{string(c.RawSubject), string(c.RawSubjectPublicKeyInfo)}] {
			continue
		}
		seen[fp] = true
		s.cross = append(s.cross, c)
		s.crossBySubject[string(c.RawSubject)] = append(s.crossBySubject[string(c.RawSubject)], c)
		if len(c.SubjectKeyId) > 0 {
			s.crossBySKI[string(c.SubjectKeyId)] = append(s.crossBySKI[string(c.SubjectKeyId)], c)
		}
	}
}

// CrossSigns returns the cross-signs that match the current roots.
func (s *Store) CrossSigns() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*x509.Certificate(nil), s.cross...)
}

// Contains reports whether any program includes the root.
func (s *Store) Contains(fp string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byFP[fp]
	return ok
}

// Trust returns a copy of the root's trust level per program (nil if the
// root is not in the store).
func (s *Store) Trust(fp string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.trust[fp]
	if t == nil {
		return nil
	}
	out := make(map[string]string, len(t))
	for k, v := range t {
		out[k] = v
	}
	return out
}

// CandidateIssuers returns roots that may have issued c (by AKI or subject).
// Callers must still verify the signature.
func (s *Store) CandidateIssuers(c *x509.Certificate) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return candidates(c, s.bySKI, s.bySubject)
}

// CandidateCrossSigns returns cross-signs that may have issued c (by AKI or
// subject). Callers must still verify the signature.
func (s *Store) CandidateCrossSigns(c *x509.Certificate) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return candidates(c, s.crossBySKI, s.crossBySubject)
}

func candidates(c *x509.Certificate, bySKI, bySubject map[string][]*x509.Certificate) []*x509.Certificate {
	seen := map[*x509.Certificate]bool{}
	var out []*x509.Certificate
	add := func(list []*x509.Certificate) {
		for _, r := range list {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	if len(c.AuthorityKeyId) > 0 {
		add(bySKI[string(c.AuthorityKeyId)])
	}
	add(bySubject[string(c.RawIssuer)])
	return out
}

// Info returns metadata about the loaded store.
func (s *Store) Info() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := map[string]int{}
	for _, t := range s.trust {
		for st, lvl := range t {
			if lvl == Trusted {
				counts[st]++
			}
		}
	}
	info := Info{Source: s.source, Count: len(s.byFP), LoadedAt: s.loadedAt, Stores: counts, CrossSigns: len(s.cross), RefreshFailing: s.refreshFailing}
	if s.refreshFailing && !s.nextAttempt.IsZero() {
		next := s.nextAttempt
		info.NextAttempt = &next
	}
	return info
}

// Sources are the three CCADB reports the store is built from.
type Sources struct {
	MozillaPEM   []byte // Mozilla included roots, Websites trust bit (PEM)
	StoresCSV    []byte // AllIncludedRootCertsCSV: status per program
	MicrosoftCSV []byte // Microsoft included CA report with PEM
	// CrossSignsPEM: cross-signs of included roots (PEM). Optional; the
	// live equivalent is the intermediate report at Loader.IntermediatesURL.
	CrossSignsPEM []byte
}

// Build parses the CCADB reports into roots and per-program trust.
func Build(src Sources) ([]*x509.Certificate, map[string]map[string]string, error) {
	trust, err := parseStatus(src.StoresCSV)
	if err != nil {
		return nil, nil, fmt.Errorf("store status CSV: %w", err)
	}
	certs := ParsePEMBundle(src.MozillaPEM)
	ms, err := parseMicrosoftPEM(src.MicrosoftCSV)
	if err != nil {
		return nil, nil, fmt.Errorf("Microsoft CSV: %w", err)
	}
	certs = append(certs, ms...)
	have := map[string]bool{}
	for _, c := range certs {
		have[FingerprintSHA256(c)] = true
	}
	counts := map[string]int{}
	missing := 0
	for fp, t := range trust {
		if !have[fp] {
			missing++
			continue
		}
		for st, lvl := range t {
			if lvl == Trusted {
				counts[st]++
			}
		}
	}
	if missing > 0 {
		slog.Warn("trust store: roots listed without a certificate", "count", missing)
	}
	for _, st := range AllStores {
		if counts[st] < 50 { // every program has well over 50 server roots
			return nil, nil, fmt.Errorf("only %d %s roots found; refusing to use this data", counts[st], st)
		}
	}
	return certs, trust, nil
}

func readCSV(data []byte) ([]map[string]string, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("no rows")
	}
	var out []map[string]string
	for _, row := range rows[1:] {
		m := map[string]string{}
		for i, k := range rows[0] {
			if i < len(row) {
				m[strings.TrimSpace(k)] = strings.TrimSpace(row[i])
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func requireCols(row map[string]string, cols ...string) error {
	for _, c := range cols {
		if _, ok := row[c]; !ok {
			return fmt.Errorf("missing column %q", c)
		}
	}
	return nil
}

// parseStatus reads which programs include each root for server
// authentication.
func parseStatus(data []byte) (map[string]map[string]string, error) {
	rows, err := readCSV(data)
	if err != nil {
		return nil, err
	}
	if err := requireCols(rows[0], "SHA-256 Fingerprint", "Apple Status", "Apple Trust Bits",
		"Google Chrome Status", "Microsoft Status", "Microsoft EKUs", "Mozilla Status", "Mozilla Trust Bits"); err != nil {
		return nil, err
	}
	out := map[string]map[string]string{}
	for _, r := range rows {
		fp := strings.ToLower(r["SHA-256 Fingerprint"])
		if len(fp) != 64 {
			continue
		}
		t := map[string]string{}
		if r["Mozilla Status"] == "Included" && strings.Contains(r["Mozilla Trust Bits"], "Websites") {
			t[Mozilla] = Trusted
		}
		if r["Apple Status"] == "Included" && strings.Contains(r["Apple Trust Bits"], "serverAuth") {
			t[Apple] = Trusted
		}
		if r["Google Chrome Status"] == "Included" {
			t[Chrome] = Trusted // Chrome's store is for server authentication only
		}
		if strings.Contains(r["Microsoft EKUs"], "Server Authentication") {
			switch r["Microsoft Status"] {
			case "Included":
				t[Microsoft] = Trusted
			case "NotBefore":
				t[Microsoft] = Limited
			}
		}
		if len(t) > 0 {
			out[fp] = t
		}
	}
	return out, nil
}

// ParseIntermediatesCSV reads the certificates from CCADB's intermediate
// certificate report (PublicAllIntermediateCertsWithPEMCSV).
func ParseIntermediatesCSV(data []byte) ([]*x509.Certificate, error) {
	certs, err := parseMicrosoftPEM(data)
	if err == nil && len(certs) == 0 {
		err = fmt.Errorf("no certificates")
	}
	return certs, err
}

func parseMicrosoftPEM(data []byte) ([]*x509.Certificate, error) {
	rows, err := readCSV(data)
	if err != nil {
		return nil, err
	}
	if err := requireCols(rows[0], "PEM Info"); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, r := range rows {
		// The intermediate report wraps each PEM in single quotes.
		buf.WriteString(strings.Trim(r["PEM Info"], "'"))
		buf.WriteByte('\n')
	}
	return ParsePEMBundle(buf.Bytes()), nil
}

// Loader keeps a Store refreshed from CCADB, falling back to embedded copies
// of the same reports.
type Loader struct {
	Store        *Store
	MozillaURL   string
	StoresURL    string
	MicrosoftURL string
	// IntermediatesURL is CCADB's intermediate report, the source of
	// cross-signs. Empty keeps the embedded cross-signs.
	IntermediatesURL string
	Fallback         Sources
	FallbackDate     time.Time // when the embedded reports were downloaded
	Client           *http.Client
	// Retry back-off after a failed download; zero means the defaults.
	RetryMin, RetryMax time.Duration
}

// Retry delays after a failed download: RetryMin, doubling each time, at
// most RetryMax (and never longer than the normal refresh interval).
const (
	DefaultRetryMin = time.Minute
	DefaultRetryMax = time.Hour
)

// Init loads the embedded reports immediately, then tries the live ones.
// It returns the live download's error, if any.
func (l *Loader) Init(ctx context.Context) error {
	if l.Store == nil {
		l.Store = &Store{}
	}
	if certs, trust, err := Build(l.Fallback); err == nil {
		l.Store.set(certs, trust, "embedded snapshot", l.FallbackDate)
		l.Store.SetCrossSigns(ParsePEMBundle(l.Fallback.CrossSignsPEM))
	} else {
		slog.Error("embedded trust store snapshot is unusable", "err", err)
	}
	return l.Refresh(ctx)
}

// Refresh fetches all three reports; if any fails the current store is kept.
func (l *Loader) Refresh(ctx context.Context) error {
	if l.MozillaURL == "" || l.StoresURL == "" || l.MicrosoftURL == "" {
		return nil
	}
	var src Sources
	for _, f := range []struct {
		url string
		dst *[]byte
	}{{l.MozillaURL, &src.MozillaPEM}, {l.StoresURL, &src.StoresCSV}, {l.MicrosoftURL, &src.MicrosoftCSV}} {
		var err error
		if *f.dst, err = l.fetch(ctx, f.url); err != nil {
			slog.Warn("trust store refresh failed; keeping current store", "url", f.url, "err", err, "source", l.Store.Info().Source, "roots", l.Store.Info().Count)
			return fmt.Errorf("%s: %w", f.url, err)
		}
	}
	certs, trust, err := Build(src)
	if err != nil {
		slog.Warn("trust store refresh failed; keeping current store", "err", err, "source", l.Store.Info().Source, "roots", l.Store.Info().Count)
		return err
	}
	l.Store.set(certs, trust, "CCADB", time.Now())
	l.refreshCrossSigns(ctx)
	info := l.Store.Info()
	slog.Info("trust store refreshed", "roots", info.Count, "stores", info.Stores, "crossSigns", info.CrossSigns)
	return nil
}

// refreshCrossSigns downloads the intermediate report. Cross-signs are extra
// information, so a failure only logs and keeps the current ones.
func (l *Loader) refreshCrossSigns(ctx context.Context) {
	if l.IntermediatesURL == "" {
		return
	}
	data, err := l.fetch(ctx, l.IntermediatesURL)
	var certs []*x509.Certificate
	if err == nil {
		certs, err = ParseIntermediatesCSV(data)
	}
	if err != nil {
		slog.Warn("cross-sign refresh failed; keeping current cross-signs", "url", l.IntermediatesURL, "err", err)
		return
	}
	l.Store.SetCrossSigns(certs)
}

// RetryDelay is the wait before retry number n (1 for the first retry).
func RetryDelay(n int, min, max time.Duration) time.Duration {
	d := min
	for i := 1; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

func (l *Loader) fetch(ctx context.Context, url string) ([]byte, error) {
	cl := l.Client
	if cl == nil {
		cl = &http.Client{Timeout: 60 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ca-chain-check")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// Run refreshes on the given interval until ctx is done. lastErr is the
// result of the download Init made. After a failed download it retries
// sooner, backing off from RetryMin to RetryMax, then returns to the normal
// interval once a download succeeds.
func (l *Loader) Run(ctx context.Context, every time.Duration, lastErr error) {
	min, max := l.RetryMin, l.RetryMax
	if min <= 0 {
		min = DefaultRetryMin
	}
	if max <= 0 {
		max = DefaultRetryMax
	}
	if max > every {
		max = every
	}
	failures := 0
	for {
		wait := every
		if lastErr != nil {
			failures++
			wait = RetryDelay(failures, min, max)
			// Up to 10% jitter so replicas don't retry in step.
			wait += time.Duration(rand.Int64N(int64(wait)/10 + 1))
			slog.Info("trust store download will be retried", "in", wait.Round(time.Second).String(), "failures", failures)
		} else {
			failures = 0
		}
		l.Store.setStatus(lastErr != nil, time.Now().UTC().Add(wait))
		t := time.NewTimer(wait)
		select {
		case <-t.C:
			lastErr = l.Refresh(ctx)
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
}

// Label is the display name of a root program.
func Label(store string) string {
	switch store {
	case Apple:
		return "Apple"
	case Chrome:
		return "Chrome"
	case Microsoft:
		return "Microsoft"
	case Mozilla:
		return "Mozilla"
	}
	return store
}

// SortStores orders program IDs as in AllStores.
func SortStores(s []string) {
	rank := map[string]int{}
	for i, st := range AllStores {
		rank[st] = i
	}
	sort.Slice(s, func(i, j int) bool { return rank[s[i]] < rank[s[j]] })
}
