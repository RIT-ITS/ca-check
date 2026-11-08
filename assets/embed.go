// Package assets embeds build-time data files.
package assets

import _ "embed"

// MozillaRootsPEM is a snapshot of the CCADB Mozilla roots (Websites trust
// bit) used when the live list cannot be fetched. Refresh with `make refresh-roots`.
//
//go:embed mozilla-roots.pem
var MozillaRootsPEM []byte
