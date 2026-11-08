// Package web embeds the static frontend.
package web

import "embed"

//go:embed index.html help.html help.js app.js styles.css vendor/mermaid.min.js fonts/PublicSans-Variable.ttf fonts/OFL.txt
var FS embed.FS
