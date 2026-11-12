package web

import (
	"os"
	"strings"
	"testing"

	"ca-chain-check/internal/analyze"
)

// TestDiagramKeyText checks app.js has key text for every diagram style.
// The UI leaves out key entries it has no text for, so a missing one would
// silently drop that style from the key.
func TestDiagramKeyText(t *testing.T) {
	js, err := os.ReadFile("app.js")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(js), "const KEY_TEXT = {")
	end := strings.Index(string(js)[start:], "\n  };")
	if start < 0 || end < 0 {
		t.Fatal("KEY_TEXT not found in app.js")
	}
	keyText := string(js)[start : start+end]
	for _, id := range analyze.DiagramStyleIDs() {
		if !strings.Contains(keyText, "\n    "+id+": [") && !strings.Contains(keyText, `"`+id+`": [`) {
			t.Errorf("app.js KEY_TEXT has no entry for diagram style %q", id)
		}
	}
}
