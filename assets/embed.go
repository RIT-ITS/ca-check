// Package assets embeds build-time data files.
package assets

import _ "embed"

// Snapshots of the CCADB reports the trust store is built from, used when
// the live reports cannot be fetched. Refresh with `make refresh-roots`.
var (
	// MozillaRootsPEM: Mozilla roots with the Websites trust bit.
	//go:embed mozilla-roots.pem
	MozillaRootsPEM []byte
	// RootStoresCSV: CCADB AllIncludedRootCertsCSV (status per root program).
	//go:embed root-stores.csv
	RootStoresCSV []byte
	// MicrosoftRootsCSV: Microsoft's included CA report, with PEM.
	//go:embed microsoft-roots.csv
	MicrosoftRootsCSV []byte
)
