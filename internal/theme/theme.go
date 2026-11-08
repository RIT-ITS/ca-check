// Package theme turns the THEME_COLORS setting into a stylesheet that
// overrides the default colour tokens in web/styles.css, so a deployment can
// use its own institution's colours without changing the shared code.
package theme

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Tokens lists the CSS custom properties a theme may set (without the
// leading "--"). Status colours (pass/warn/fail/note) are deliberately not
// themeable: they carry meaning and are tuned for contrast.
var Tokens = map[string]bool{
	"accent": true, "accent-ink": true, "accent-hover": true,
	"bar": true, "bar-ink": true, "bar-muted": true, "bar-field": true, "bar-line": true,
	"bar-line-hover": true, "bar-placeholder": true, "bar-error": true, "bar-edge": true,
	"ground": true, "sheet": true, "sheet-alt": true, "ink": true, "muted": true,
	"rule": true, "rule-strong": true, "link": true,
}

// schemeSplit are tokens that web/styles.css redefines for dark mode. An
// unprefixed value for one of these applies to light mode only; use the
// "dark." prefix to set its dark-mode value. Every other token applies to
// both schemes.
var schemeSplit = map[string]bool{
	"bar": true, "bar-field": true, "ground": true, "sheet": true, "sheet-alt": true,
	"ink": true, "muted": true, "rule": true, "rule-strong": true, "link": true,
}

// Defaults for the two colours drawn into the favicon. They must match the
// defaults in web/styles.css (a test checks this).
const (
	DefaultBar     = "#1b2a41"
	DefaultBarEdge = "#f2c230"
)

// Entry is one validated colour assignment.
type Entry struct {
	Token string // e.g. "accent"
	Dark  bool   // set via the "dark." prefix
	Value string // normalised "#rrggbb" style hex
}

var hexRe = regexp.MustCompile(`^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

// Parse reads "token=#hex;dark.token=#hex". Entries may be separated by ";",
// "," or whitespace, and the "#" is optional so values survive .env parsers
// that treat "#" as a comment.
func Parse(s string) ([]Entry, error) {
	var out []Entry
	seen := map[string]int{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
	}) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("THEME_COLORS: %q is not token=colour", part)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		k = strings.TrimPrefix(k, "--")
		e := Entry{Token: k}
		if rest, found := strings.CutPrefix(k, "dark."); found {
			e.Dark, e.Token = true, rest
		}
		if !Tokens[e.Token] {
			return nil, fmt.Errorf("THEME_COLORS: unknown token %q (allowed: %s)", e.Token, strings.Join(TokenNames(), ", "))
		}
		m := hexRe.FindStringSubmatch(strings.TrimSpace(v))
		if m == nil {
			return nil, fmt.Errorf("THEME_COLORS: %s=%q is not a hex colour", k, v)
		}
		e.Value = "#" + strings.ToLower(m[1])
		key := k
		if i, dup := seen[key]; dup {
			out[i] = e // last one wins
			continue
		}
		seen[key] = len(out)
		out = append(out, e)
	}
	return out, nil
}

// TokenNames returns the allowed token names, sorted.
func TokenNames() []string {
	names := make([]string, 0, len(Tokens))
	for k := range Tokens {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// CSS renders the overrides. Values are validated hex, so nothing here can
// inject CSS.
func CSS(entries []Entry) string {
	var both, light, dark []string
	for _, e := range entries {
		decl := fmt.Sprintf("  --%s: %s;", e.Token, e.Value)
		switch {
		case e.Dark:
			dark = append(dark, decl)
		case schemeSplit[e.Token]:
			light = append(light, decl)
		default:
			both = append(both, decl)
		}
	}
	var b strings.Builder
	b.WriteString("/* Local theme from THEME_COLORS. Empty when the defaults are in use. */\n")
	if len(both) > 0 {
		fmt.Fprintf(&b, ":root {\n%s\n}\n", strings.Join(both, "\n"))
	}
	if len(light) > 0 {
		fmt.Fprintf(&b, "@media not all and (prefers-color-scheme: dark) {\n:root {\n%s\n}\n}\n", strings.Join(light, "\n"))
	}
	if len(dark) > 0 {
		fmt.Fprintf(&b, "@media (prefers-color-scheme: dark) {\n:root {\n%s\n}\n}\n", strings.Join(dark, "\n"))
	}
	return b.String()
}

// Favicon draws the tab icon in the theme's band and edge colours.
func Favicon(entries []Entry) []byte {
	bar, edge := DefaultBar, DefaultBarEdge
	for _, e := range entries {
		if e.Dark {
			continue
		}
		switch e.Token {
		case "bar":
			bar = e.Value
		case "bar-edge":
			edge = e.Value
		}
	}
	return []byte(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="%s"/><rect y="27" width="32" height="5" fill="%s"/><path d="M8 9h7v5H8zm9 6h7v5h-7zM11.5 14v3.5H17" fill="none" stroke="#fff" stroke-width="2"/></svg>`, bar, edge))
}
