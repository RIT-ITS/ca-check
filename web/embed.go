// Package web embeds the static frontend.
package web

import "embed"

//go:embed index.html help.html help.js swagger.html swagger.js openapi.json app.js styles.css vendor/mermaid.min.js vendor/swagger-ui/swagger-ui-bundle.js vendor/swagger-ui/swagger-ui.css vendor/swagger-ui/LICENSE fonts/plex
var FS embed.FS
