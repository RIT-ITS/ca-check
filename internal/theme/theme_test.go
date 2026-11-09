package theme

import (
	"bytes"
	"encoding/binary"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
)

func TestParseAndCSS(t *testing.T) {
	es, err := Parse("accent=#C0FFEE; bar=101010;dark.bar=#050505, bar-edge=c0ffee\naccent=#c0ffef")
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 4 || es[0].Value != "#c0ffef" {
		t.Fatalf("entries = %+v", es)
	}
	css := CSS(es)
	for _, want := range []string{
		":root {\n  --accent: #c0ffef;\n  --bar-edge: #c0ffee;\n}",
		"@media not all and (prefers-color-scheme: dark) {\n:root {\n  --bar: #101010;",
		"@media (prefers-color-scheme: dark) {\n:root {\n  --bar: #050505;",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("CSS missing %q:\n%s", want, css)
		}
	}
	fav := string(Favicon(es))
	if !strings.Contains(fav, `fill="#101010"`) || !strings.Contains(fav, `fill="#c0ffee"`) {
		t.Errorf("favicon not themed: %s", fav)
	}
}

func TestParseRejects(t *testing.T) {
	for _, s := range []string{
		"accent=red",
		"accent=#fff;}body{display:none",
		"fail=#000000",
		"accent",
		"dark.nope=#000",
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
	if es, err := Parse(""); err != nil || len(es) != 0 || strings.Contains(CSS(es), "{") {
		t.Errorf("empty theme: %v %v", es, err)
	}
}

// The favicon defaults must match the stylesheet defaults.
func TestDefaultsMatchStylesheet(t *testing.T) {
	css, err := os.ReadFile("../../web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--bar: " + DefaultBar + ";", "--bar-edge: " + DefaultBarEdge + ";"} {
		if !strings.Contains(string(css), want) {
			t.Errorf("styles.css lacks %q", want)
		}
	}
	for tok := range Tokens {
		if !strings.Contains(string(css), "--"+tok+":") {
			t.Errorf("token %q is not defined in styles.css", tok)
		}
	}
}

func TestRasterIcons(t *testing.T) {
	es, err := Parse("bar=101010 bar-edge=c0ffee")
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(IconPNG(es, 32, true)))
	if err != nil {
		t.Fatal(err)
	}
	at := func(x, y int) color.NRGBA { return color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA) }
	for _, c := range []struct {
		x, y int
		want color.NRGBA
	}{
		{0, 0, color.NRGBA{}},                        // rounded corner is transparent
		{3, 20, color.NRGBA{0x10, 0x10, 0x10, 255}},  // bar
		{16, 30, color.NRGBA{0xc0, 0xff, 0xee, 255}}, // bottom band
		{11, 9, color.NRGBA{255, 255, 255, 255}},     // stroke
	} {
		if got := at(c.x, c.y); got != c.want {
			t.Errorf("pixel (%d,%d) = %v, want %v", c.x, c.y, got, c.want)
		}
	}
	touch, _ := png.Decode(bytes.NewReader(IconPNG(es, 180, false)))
	if _, _, _, a := touch.At(0, 0).RGBA(); a != 0xffff {
		t.Error("apple-touch-icon corner should be opaque")
	}
	ico := FaviconICO(es)
	if len(ico) < 6 || ico[2] != 1 || ico[4] != 3 {
		t.Fatalf("bad ICO header % x", ico[:6])
	}
	for i := 0; i < 3; i++ {
		e := ico[6+16*i:]
		size, off := int(e[0]), int(binary.LittleEndian.Uint32(e[12:]))
		m, err := png.Decode(bytes.NewReader(ico[off:]))
		if err != nil || m.Bounds().Dx() != size {
			t.Errorf("ICO image %d: size %d, err %v", i, size, err)
		}
	}
}
