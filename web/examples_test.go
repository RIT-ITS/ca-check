package web

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestHelpExamplesMatchRepo keeps the scripts shown on the help page the
// same as the copies in examples/.
func TestHelpExamplesMatchRepo(t *testing.T) {
	page, err := os.ReadFile("help.html")
	if err != nil {
		t.Fatal(err)
	}
	for id, file := range map[string]string{
		"script-bash":       "cacheck.sh",
		"script-powershell": "cacheck.ps1",
		"script-python":     "cacheck.py",
	} {
		re := regexp.MustCompile(`(?s)<h3 id="` + id + `">.*?<pre class="code"[^>]*><code>(.*?)</code></pre>`)
		m := re.FindSubmatch(page)
		if m == nil {
			t.Errorf("help.html: no code block after #%s", id)
			continue
		}
		shown := html.UnescapeString(strings.ReplaceAll(string(m[1]), `<span data-origin>https://this-server</span>`, "https://this-server"))
		want, err := os.ReadFile(filepath.Join("..", "examples", file))
		if err != nil {
			t.Fatal(err)
		}
		if shown != strings.TrimRight(string(want), "\n") {
			t.Errorf("help.html #%s differs from examples/%s", id, file)
		}
	}
}
