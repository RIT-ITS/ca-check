package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

const fp = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
const fpNorm = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := LoadFrom(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimitRPM != 10 || c.RateLimitBurst != 5 || c.MaxIPsPerHost != 16 || !c.AllowRequestIPOverride {
		t.Errorf("defaults: %+v", c)
	}
	if len(c.TargetDenyCIDRs) != len(DefaultDenyCIDRs) || len(c.PrivateTargetClientCIDRs) != 0 {
		t.Errorf("cidrs: %v %v", c.TargetDenyCIDRs, c.PrivateTargetClientCIDRs)
	}
}

func TestPendingDistrustEnv(t *testing.T) {
	got := ParsePendingDistrustEnv(fp + "|2026-12-31|Example CA distrust;" + fpNorm[:62] + "zz;" + fp)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Fingerprint != fpNorm || got[0].Date != "2026-12-31" || got[0].Note != "Example CA distrust" {
		t.Errorf("entry 0: %+v", got[0])
	}
	if got[1].Fingerprint != fpNorm || got[1].Date != "" {
		t.Errorf("entry 1: %+v", got[1])
	}
	// colon-free fingerprint with ':' separators
	got = ParsePendingDistrustEnv(fpNorm + ":2027-03-01:note: with colon")
	if len(got) != 1 || got[0].Date != "2027-03-01" || got[0].Note != "note: with colon" {
		t.Errorf("colon form: %+v", got)
	}
}

func TestPendingDistrustFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pd.yaml")
	os.WriteFile(f, []byte("- fingerprint: \""+fp+"\"\n  date: 2027-01-01\n  note: from file\n- fingerprint: bogus\n"), 0o600)
	c, err := LoadFrom(env(map[string]string{"PENDING_DISTRUST_FILE": f}))
	if err != nil {
		t.Fatal(err)
	}
	if pd, ok := c.PendingDistrust[fpNorm]; !ok || pd.Note != "from file" || len(c.PendingDistrust) != 1 {
		t.Errorf("got %+v", c.PendingDistrust)
	}
}

func TestDNSOverrides(t *testing.T) {
	m, err := ParseDNSOverrides("api.internal=10.0.0.5, 10.0.0.6; *.svc.cluster.local=10.96.0.10;V6.Example.=::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(m["api.internal"]) != 2 || m["*.svc.cluster.local"][0] != netip.MustParseAddr("10.96.0.10") || len(m["v6.example"]) != 1 {
		t.Errorf("got %v", m)
	}
	if _, err := ParseDNSOverrides("nohost"); err == nil {
		t.Error("expected error")
	}
	if _, err := ParseDNSOverrides("a=notanip"); err == nil {
		t.Error("expected error")
	}
}

func TestInvalidValues(t *testing.T) {
	for k, v := range map[string]string{
		"RATE_LIMIT_RPM": "0", "MAX_IPS_PER_HOST": "x", "DIAL_TIMEOUT": "-1s",
		"TRUSTED_PROXIES": "10.0.0.0/33", "ALLOWED_PORTS": "70000",
	} {
		if _, err := LoadFrom(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%s: expected error", k, v)
		}
	}
}
