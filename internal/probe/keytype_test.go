package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"ca-chain-check/internal/testpki"
)

// tlsServer serves TLS with the given certificates and version range.
func tlsServer(t *testing.T, min, max uint16, certs ...tls.Certificate) *Prober {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs, MinVersion: min, MaxVersion: max})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	cfg := testCfg(t)
	cfg.HandshakeTimeout = 3 * time.Second
	cfg.CheckAltKeyType = true
	addr := ln.Addr().String()
	return &Prober{Cfg: cfg, Sem: make(chan struct{}, 4), Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
}

func certs(t *testing.T) (ecdsaCert, rsaCert tls.Certificate) {
	t.Helper()
	root := testpki.Root("Key Type Root")
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec := testpki.Leaf("dual.example.test", root)
	rs := testpki.Leaf("dual.example.test", root, testpki.Opts{Key: k})
	return testpki.TLSCert(ec, root), testpki.TLSCert(rs, root)
}

func probeIP(t *testing.T, p *Prober) *IPResult {
	t.Helper()
	r := &IPResult{IP: "127.0.0.1"}
	p.probeOne(t.Context(), mustAddr("127.0.0.1"), r, "dual.example.test", 443, "", "", mustAddr("127.0.0.1"))
	if r.Error != "" {
		t.Fatalf("probe: %s", r.Error)
	}
	return r
}

func TestBothKeyTypes(t *testing.T) {
	ec, rs := certs(t)
	r := probeIP(t, tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, ec, rs))
	if r.KeyType != "ecdsa" || r.Alternate == nil || r.Alternate.KeyType != "rsa" {
		t.Fatalf("keyType %q alternate %+v note %q", r.KeyType, r.Alternate, r.KeyTypeNote)
	}
	if r.Alternate.TLS.Version != "TLS 1.2" || r.Alternate.Analysis == nil {
		t.Errorf("alternate tls %+v", r.Alternate.TLS)
	}
	if !strings.Contains(r.chainKey, "|") {
		t.Errorf("chain key should cover both chains: %q", r.chainKey)
	}
}

func TestOnlyOneKeyType(t *testing.T) {
	ec, _ := certs(t)
	r := probeIP(t, tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, ec))
	if r.Alternate != nil || r.KeyTypeNote != "The server has only an ECDSA certificate." {
		t.Fatalf("alternate %+v note %q", r.Alternate, r.KeyTypeNote)
	}
}

func TestTLS13OnlyCannotAskForOtherKeyType(t *testing.T) {
	_, rs := certs(t)
	r := probeIP(t, tlsServer(t, tls.VersionTLS13, tls.VersionTLS13, rs))
	if r.KeyType != "rsa" || r.Alternate != nil || !strings.Contains(r.KeyTypeNote, "only allows TLS 1.3") {
		t.Fatalf("keyType %q note %q", r.KeyType, r.KeyTypeNote)
	}
}

func TestAltKeyTypeOff(t *testing.T) {
	ec, rs := certs(t)
	p := tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, ec, rs)
	p.Cfg.CheckAltKeyType = false
	if r := probeIP(t, p); r.Alternate != nil || r.KeyTypeNote != "" {
		t.Fatalf("alternate %+v note %q", r.Alternate, r.KeyTypeNote)
	}
}

func TestFetchChain12ReadsStaple(t *testing.T) {
	ec, rs := certs(t)
	rs.OCSPStaple = []byte("staple")
	p := tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, ec, rs)
	certs, info, err := p.attempt(t.Context(), "dual.example.test", 443, "", mustAddr("127.0.0.1"), "rsa")
	if err != nil {
		t.Fatal(err)
	}
	if keyType(certs[0]) != "rsa" || len(certs) != 2 || string(info.staple) != "staple" || info.Version != "TLS 1.2" {
		t.Fatalf("%s, %d certs, staple %q, %s", keyType(certs[0]), len(certs), info.staple, info.Version)
	}
}

// The main handshake's stapled response reaches the analysis.
func TestStaplePassedToAnalysis(t *testing.T) {
	ec, _ := certs(t)
	ec.OCSPStaple = []byte("not a real response")
	r := probeIP(t, tlsServer(t, tls.VersionTLS12, tls.VersionTLS13, ec))
	if r.Analysis.Staple == nil || !r.Analysis.Staple.Present {
		t.Fatalf("staple = %+v", r.Analysis.Staple)
	}
}
