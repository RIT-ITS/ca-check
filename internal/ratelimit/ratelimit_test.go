package ratelimit

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"ca-chain-check/internal/config"
)

func TestClientIP(t *testing.T) {
	trusted, _ := config.ParseCIDRList("10.0.0.0/8")
	cases := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1234", "", "203.0.113.9"},
		{"203.0.113.9:1234", "1.1.1.1", "203.0.113.9"},             // untrusted peer: ignore XFF
		{"10.0.0.2:1234", "1.1.1.1", "1.1.1.1"},                    // trusted proxy
		{"10.0.0.2:1234", "6.6.6.6, 1.1.1.1, 10.0.0.3", "1.1.1.1"}, // spoofed left entry ignored
		{"10.0.0.2:1234", "", "10.0.0.2"},
		{"10.0.0.2:1234", "garbage", "10.0.0.2"},
		{"[2001:db8::1]:443", "", "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r, trusted); got != netip.MustParseAddr(c.want) {
			t.Errorf("%s / %q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := New(60, 3) // 1/s, burst 3
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	ip := netip.MustParseAddr("1.2.3.4")
	for i := 0; i < 3; i++ {
		if ok, _ := l.AllowN(ip, 1); !ok {
			t.Fatalf("request %d denied", i)
		}
	}
	ok, wait := l.AllowN(ip, 1)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("4th: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.AllowN(netip.MustParseAddr("5.6.7.8"), 1); !ok {
		t.Error("other IP should be independent")
	}
	now = now.Add(2 * time.Second)
	if ok, _ := l.AllowN(ip, 2); !ok {
		t.Error("should refill")
	}
	now = now.Add(time.Hour)
	l.Sweep()
	if len(l.buckets) != 0 {
		t.Errorf("sweep left %d buckets", len(l.buckets))
	}
}
