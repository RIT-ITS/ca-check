// Package truststore maintains the Mozilla (CCADB) root set used to decide
// whether a chain terminates in a publicly trusted root.
package truststore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Store is a read-mostly, atomically swappable set of trusted roots.
type Store struct {
	mu        sync.RWMutex
	byFP      map[string]*x509.Certificate
	bySubject map[string][]*x509.Certificate
	bySKI     map[string][]*x509.Certificate
	source    string
	loadedAt  time.Time
}

// Info describes the current store for display.
type Info struct {
	Source   string    `json:"source"`
	Count    int       `json:"count"`
	LoadedAt time.Time `json:"loadedAt"`
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

// NewFromCerts builds a store from certificates (used by tests and loaders).
func NewFromCerts(certs []*x509.Certificate, source string) *Store {
	s := &Store{}
	s.set(certs, source)
	return s
}

func (s *Store) set(certs []*x509.Certificate, source string) {
	byFP := map[string]*x509.Certificate{}
	bySubj := map[string][]*x509.Certificate{}
	bySKI := map[string][]*x509.Certificate{}
	for _, c := range certs {
		fp := FingerprintSHA256(c)
		if _, dup := byFP[fp]; dup {
			continue
		}
		byFP[fp] = c
		bySubj[string(c.RawSubject)] = append(bySubj[string(c.RawSubject)], c)
		if len(c.SubjectKeyId) > 0 {
			bySKI[string(c.SubjectKeyId)] = append(bySKI[string(c.SubjectKeyId)], c)
		}
	}
	s.mu.Lock()
	s.byFP, s.bySubject, s.bySKI = byFP, bySubj, bySKI
	s.source, s.loadedAt = source, time.Now()
	s.mu.Unlock()
}

// Contains reports whether the fingerprint is a trusted root.
func (s *Store) Contains(fp string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byFP[fp]
	return ok
}

// CandidateIssuers returns roots that may have issued c (by AKI or subject).
// Callers must still verify the signature.
func (s *Store) CandidateIssuers(c *x509.Certificate) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
		add(s.bySKI[string(c.AuthorityKeyId)])
	}
	add(s.bySubject[string(c.RawIssuer)])
	return out
}

// Info returns metadata about the loaded store.
func (s *Store) Info() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Info{Source: s.source, Count: len(s.byFP), LoadedAt: s.loadedAt}
}

// Loader keeps a Store refreshed from a URL, falling back to an embedded bundle.
type Loader struct {
	Store    *Store
	URL      string
	Fallback []byte
	Client   *http.Client
}

// Init loads the embedded bundle immediately, then tries the remote URL.
func (l *Loader) Init(ctx context.Context) {
	if l.Store == nil {
		l.Store = &Store{}
	}
	if certs := ParsePEMBundle(l.Fallback); len(certs) > 0 {
		l.Store.set(certs, "embedded snapshot")
	}
	l.Refresh(ctx)
}

// Refresh fetches the remote bundle; on failure the current store is kept.
func (l *Loader) Refresh(ctx context.Context) {
	if l.URL == "" {
		return
	}
	certs, err := l.fetch(ctx)
	if err != nil {
		slog.Warn("trust store refresh failed; keeping current store", "err", err, "source", l.Store.Info().Source)
		return
	}
	l.Store.set(certs, l.URL)
	slog.Info("trust store refreshed", "roots", len(certs))
}

func (l *Loader) fetch(ctx context.Context) ([]*x509.Certificate, error) {
	cl := l.Client
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		return nil, fmt.Errorf("response contains no certificates")
	}
	certs := ParsePEMBundle(body)
	if len(certs) < 50 { // sanity: Mozilla has ~150 roots
		return nil, fmt.Errorf("only %d roots parsed; refusing to replace store", len(certs))
	}
	return certs, nil
}

// Run refreshes on the given interval until ctx is done.
func (l *Loader) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.Refresh(ctx)
		case <-ctx.Done():
			return
		}
	}
}
