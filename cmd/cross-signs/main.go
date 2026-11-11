// Command cross-signs reads CCADB's intermediate certificate report
// (PublicAllIntermediateCertsWithPEMCSV) and prints, as PEM, the
// certificates that cross-sign a root in the embedded trust store snapshot.
// `make refresh-cross-signs` writes its output to assets/cross-signs.pem.
package main

import (
	"encoding/pem"
	"fmt"
	"os"

	"ca-chain-check/assets"
	"ca-chain-check/internal/truststore"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cross-signs INTERMEDIATES.csv > assets/cross-signs.pem")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "cross-signs:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cands, err := truststore.ParseIntermediatesCSV(data)
	if err != nil {
		return err
	}
	roots, trust, err := truststore.Build(truststore.Sources{
		MozillaPEM: assets.MozillaRootsPEM, StoresCSV: assets.RootStoresCSV, MicrosoftCSV: assets.MicrosoftRootsCSV,
	})
	if err != nil {
		return err
	}
	s := truststore.NewWithTrust(roots, trust, "")
	s.SetCrossSigns(cands)
	for _, c := range s.CrossSigns() {
		fmt.Printf("# %s\n# issued by %s\n", c.Subject, c.Issuer)
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return nil
}
