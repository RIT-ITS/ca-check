package netguard

import (
	"net/netip"
	"testing"

	"ca-chain-check/internal/config"
)

func p(s string) []netip.Prefix {
	out, err := config.ParseCIDRList(s)
	if err != nil {
		panic(err)
	}
	return out
}

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestCheckTarget(t *testing.T) {
	deny := p("0.0.0.0/8,169.254.0.0/16,224.0.0.0/4,fe80::/10,ff00::/8,10.250.0.0/16")
	g := New(deny, p("203.0.113.0/24"), p("192.168.1.0/24"), nil, true)
	outside, inside := a("198.51.100.7"), a("192.168.1.20")
	cases := []struct {
		client, target netip.Addr
		ok             bool
	}{
		{outside, a("93.184.216.34"), true},
		{outside, a("10.0.0.1"), false},
		{inside, a("10.0.0.1"), true},
		{outside, a("127.0.0.1"), false},
		{inside, a("127.0.0.1"), true},
		{inside, a("169.254.169.254"), false}, // hard deny beats allowlist
		{inside, a("10.250.1.1"), false},      // operator deny inside private range
		{outside, a("203.0.113.5"), false},    // extra private range
		{inside, a("203.0.113.5"), true},
		{outside, a("::1"), false},
		{outside, a("fd12::1"), false},
		{inside, a("fe80::1"), false},
		{outside, a("2606:4700::1111"), true},
		{outside, a("::ffff:10.0.0.1"), false}, // v4-mapped unwrapped
		{outside, a("100.64.0.1"), false},
	}
	for _, c := range cases {
		err := g.CheckTarget(c.client, c.target)
		if (err == nil) != c.ok {
			t.Errorf("client %s target %s: err=%v want ok=%v", c.client, c.target, err, c.ok)
		}
	}
}

func TestCheckOverride(t *testing.T) {
	if New(nil, nil, nil, nil, false).CheckOverride(a("1.2.3.4")) == nil {
		t.Error("disabled override allowed")
	}
	if New(nil, nil, nil, nil, true).CheckOverride(a("1.2.3.4")) != nil {
		t.Error("open override denied")
	}
	g := New(nil, nil, nil, p("10.0.0.0/8"), true)
	if g.CheckOverride(a("1.2.3.4")) == nil || g.CheckOverride(a("10.1.1.1")) != nil {
		t.Error("restricted override wrong")
	}
}
