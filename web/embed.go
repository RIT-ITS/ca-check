// Package web embeds the static frontend.
package web

import "embed"

//go:embed index.html app.js styles.css favicon.svg vendor/mermaid.min.js
var FS embed.FS
