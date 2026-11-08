package truststore

import (
	"testing"

	"ca-chain-check/assets"
)

// The embedded CCADB snapshot must build a store with every program.
func TestBuildEmbedded(t *testing.T) {
	certs, trust, err := Build(Sources{MozillaPEM: assets.MozillaRootsPEM, StoresCSV: assets.RootStoresCSV, MicrosoftCSV: assets.MicrosoftRootsCSV})
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithTrust(certs, trust, "test")
	info := s.Info()
	for _, st := range AllStores {
		if info.Stores[st] < 50 {
			t.Errorf("%s: %d roots", st, info.Stores[st])
		}
	}
	// emSign Root CA - G1 is in all four programs.
	tr := s.Trust("40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367")
	if len(tr) != 4 {
		t.Errorf("emSign G1 trust = %v", tr)
	}
	t.Logf("roots %d, per store %v", info.Count, info.Stores)
}

func TestParseStatusRules(t *testing.T) {
	csv := []byte(`"CA Owner","Certificate Name","Apple Status","Apple Trust Bits","Google Chrome Status","Microsoft Status","Microsoft EKUs","Mozilla Status","Mozilla Trust Bits","SHA-256 Fingerprint"
"A","email only","Included","emailProtection","Not Included","Included","Secure Email","Included","Email","` + hex64("a") + `"
"B","ms notbefore","Not Included","","Not Included","NotBefore","Server Authentication","Removed","","` + hex64("b") + `"
"C","all","Included","serverAuth;clientAuth","Included","Included","Server Authentication","Included","Websites;Email","` + hex64("C") + `"
`)
	got, err := parseStatus(csv)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[hex64("a")]; ok {
		t.Error("email-only root counted as trusted")
	}
	if got[hex64("b")][Microsoft] != Limited || len(got[hex64("b")]) != 1 {
		t.Errorf("NotBefore root = %v", got[hex64("b")])
	}
	if len(got[hex64("c")]) != 4 {
		t.Errorf("fully included root = %v (fingerprint should be lowercased)", got[hex64("c")])
	}
}

func hex64(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}
