package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"ca-chain-check/internal/config"
	"ca-chain-check/internal/testpki"
)

func testCfg(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{MaxIPsPerHost: 16, AllowedPorts: map[int]bool{}, DialTimeout: time.Second}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// fakeServer accepts one connection, runs the protocol's server side of
// the upgrade (accept=false makes it refuse), then completes a TLS
// handshake if it agreed.
func fakeServer(t *testing.T, proto string, accept bool) string {
	t.Helper()
	root := testpki.Root("STARTTLS Test Root")
	leaf := testpki.Leaf("mail.example.test", root)
	cert := testpki.TLSCert(leaf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go serveOne(c, proto, accept, cert)
		}
	}()
	return ln.Addr().String()
}

func serveOne(c net.Conn, proto string, accept bool, cert tls.Certificate) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	line := func() string { s, _ := r.ReadString('\n'); return strings.TrimRight(s, "\r\n") }
	ok := accept
	switch proto {
	case "smtp":
		io.WriteString(c, "220-mail.example.test ESMTP\r\n220 ready\r\n")
		line() // EHLO
		io.WriteString(c, "250-mail.example.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
		line() // STARTTLS
		if ok {
			io.WriteString(c, "220 Go ahead\r\n")
		} else {
			io.WriteString(c, "454 TLS not available\r\n")
		}
	case "ftp":
		io.WriteString(c, "220 FTP ready\r\n")
		line()
		if ok {
			io.WriteString(c, "234 AUTH TLS OK\r\n")
		} else {
			io.WriteString(c, "502 Not implemented\r\n")
		}
	case "imap":
		io.WriteString(c, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
		line()
		if ok {
			io.WriteString(c, "a1 OK Begin TLS negotiation now\r\n")
		} else {
			io.WriteString(c, "a1 NO STARTTLS unavailable\r\n")
		}
	case "pop3":
		io.WriteString(c, "+OK POP3 ready\r\n")
		line()
		if ok {
			io.WriteString(c, "+OK Begin TLS\r\n")
		} else {
			io.WriteString(c, "-ERR no TLS\r\n")
		}
	case "postgres":
		buf := make([]byte, 8)
		io.ReadFull(r, buf)
		if ok {
			c.Write([]byte{'S'})
		} else {
			c.Write([]byte{'N'})
		}
	case "mysql":
		c.Write(mysqlGreeting(ok))
		if !ok {
			return
		}
		req := make([]byte, 36)
		if _, err := io.ReadFull(r, req); err != nil || req[0] != 32 || req[3] != 1 ||
			binary.LittleEndian.Uint32(req[4:])&mysqlSSL == 0 {
			return
		}
	case "ldap":
		buf := make([]byte, len(ldapStartTLSRequest))
		io.ReadFull(r, buf)
		code := byte(0)
		if !ok {
			code = 2 // protocolError
		}
		// LDAPMessage{ id 1, ExtendedResponse{ resultCode, matchedDN "", diagnosticMessage "" } }
		c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00})
	}
	if !ok {
		return
	}
	// The client's TLS bytes may already be buffered in r.
	tc := tls.Server(&bufConn{Conn: c, r: r}, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = tc.Handshake()
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestStartTLS(t *testing.T) {
	for _, proto := range StartTLSNames() {
		t.Run(proto, func(t *testing.T) {
			addr := fakeServer(t, proto, true)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if err := startTLS(c, proto); err != nil {
				t.Fatalf("startTLS: %v", err)
			}
			tc := tls.Client(c, &tls.Config{ServerName: "mail.example.test", InsecureSkipVerify: true}) //nolint:gosec // test
			if err := tc.Handshake(); err != nil {
				t.Fatalf("handshake after STARTTLS: %v", err)
			}
			if cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "mail.example.test" {
				t.Errorf("leaf CN %q", cn)
			}
		})
		t.Run(proto+"-refused", func(t *testing.T) {
			addr := fakeServer(t, proto, false)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if err := startTLS(c, proto); err == nil {
				t.Fatal("refusal not reported")
			}
		})
	}
}

func TestStartTLSPlan(t *testing.T) {
	p := &Prober{Cfg: testCfg(t)}
	req := &Request{Host: "127.0.0.1", StartTLS: "SMTP"}
	if _, _, _, err := p.Plan(t.Context(), mustAddr("127.0.0.1"), req); err != nil {
		t.Fatal(err)
	}
	if req.StartTLS != "smtp" || req.Port != 25 {
		t.Errorf("got starttls %q port %d, want smtp 25", req.StartTLS, req.Port)
	}
	// Common STARTTLS ports fall back to STARTTLS after TLS; "none" or an
	// explicit protocol turns the fallback off.
	for _, c := range []struct {
		port         int
		starttls     string
		wantStart    string
		wantFallback string
	}{
		{587, "", "", "smtp"}, {143, "", "", "imap"}, {443, "", "", ""}, {0, "", "", ""},
		{25, "none", "", ""}, {3306, "", "mysql", ""}, {3306, "none", "", ""}, {465, "", "", ""}, {993, "", "", ""}, {2525, "smtp", "smtp", ""},
	} {
		req := &Request{Host: "127.0.0.1", Port: c.port, StartTLS: c.starttls}
		if _, _, _, err := p.Plan(t.Context(), mustAddr("127.0.0.1"), req); err != nil {
			t.Fatal(err)
		}
		if req.StartTLS != c.wantStart || req.Fallback != c.wantFallback {
			t.Errorf("port %d starttls %q: got starttls %q fallback %q, want %q %q", c.port, c.starttls, req.StartTLS, req.Fallback, c.wantStart, c.wantFallback)
		}
	}
	req = &Request{Host: "127.0.0.1", StartTLS: "gopher"}
	if _, _, _, err := p.Plan(t.Context(), mustAddr("127.0.0.1"), req); err == nil || !strings.Contains(err.Error(), "unsupported STARTTLS") {
		t.Errorf("unknown protocol: err = %v", err)
	}
}

// On a common STARTTLS port the probe tries TLS first, then falls back to
// STARTTLS when the TLS handshake fails.
func TestHandshakeFallsBackToStartTLS(t *testing.T) {
	addr := fakeServer(t, "smtp", true)
	cfg := testCfg(t)
	cfg.HandshakeTimeout = 3 * time.Second
	p := &Prober{Cfg: cfg, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	certs, info, err := p.handshake(t.Context(), "mail.example.test", 25, "", "smtp", mustAddr("127.0.0.1"))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if info.StartTLS != "smtp" || len(certs) == 0 {
		t.Errorf("starttls %q, %d certs", info.StartTLS, len(certs))
	}
	// Without a fallback the TLS failure is reported as is.
	if _, _, err := p.handshake(t.Context(), "mail.example.test", 25, "", "", mustAddr("127.0.0.1")); err == nil {
		t.Error("plain TLS against an SMTP server should fail")
	}
	// Refusal of both is reported with both reasons.
	p.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fakeServer(t, "smtp", false))
	}
	if _, _, err := p.handshake(t.Context(), "mail.example.test", 25, "", "smtp", mustAddr("127.0.0.1")); err == nil || !strings.Contains(err.Error(), "STARTTLS (smtp) also failed") {
		t.Errorf("both failing: err = %v", err)
	}
}

// mysqlGreeting builds a HandshakeV10 packet; withTLS sets CLIENT_SSL.
func mysqlGreeting(withTLS bool) []byte {
	caps := uint16(0xf7ff &^ mysqlSSL)
	if withTLS {
		caps |= mysqlSSL
	}
	body := []byte{10}
	body = append(body, "8.4.3\x00"...)
	body = append(body, 1, 0, 0, 0)    // connection ID
	body = append(body, "abcdefgh"...) // auth data part 1
	body = append(body, 0, byte(caps), byte(caps>>8), 45, 2, 0, 0xff, 0xc1, 21)
	body = append(body, make([]byte, 10)...) // reserved
	body = append(body, "ijklmnopqrst\x00mysql_native_password\x00"...)
	return append([]byte{byte(len(body)), 0, 0, 0}, body...)
}

func TestMySQLErrors(t *testing.T) {
	for _, c := range []struct {
		name, send, want string
	}{
		{"err packet", mysqlPacket("\xff\x6a\x04Host '203.0.113.9' is not allowed to connect to this MySQL server"), "not allowed to connect to this MySQL server (error 1130)"},
		{"not mysql", "HTTP/1.1 400 Bad Request\r\n\r\n", "is this a MySQL server?"},
		{"no tls", string(mysqlGreeting(false)), "server does not support TLS"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, cli := net.Pipe()
			go func() { io.WriteString(srv, c.send); io.Copy(io.Discard, srv) }()
			defer cli.Close()
			_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
			err := startTLS(cli, "mysql")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func mysqlPacket(body string) string {
	return string([]byte{byte(len(body)), byte(len(body) >> 8), 0, 0}) + body
}
