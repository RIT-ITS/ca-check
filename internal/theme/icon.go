package theme

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"strconv"
	"strings"
)

// Raster versions of the favicon, for browsers and tools that don't use the
// SVG one: /favicon.ico (16, 32 and 48 px) and /apple-touch-icon.png (180 px).
// They draw the same picture as Favicon, in the same 32-unit grid.

// faviconColors returns the light-mode bar and bar-edge colours.
func faviconColors(entries []Entry) (bar, edge color.NRGBA) {
	b, e := DefaultBar, DefaultBarEdge
	for _, en := range entries {
		if en.Dark {
			continue
		}
		switch en.Token {
		case "bar":
			b = en.Value
		case "bar-edge":
			e = en.Value
		}
	}
	return hexColor(b), hexColor(e)
}

func hexColor(s string) color.NRGBA {
	s = strings.TrimPrefix(s, "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) == 6 {
		s += "ff"
	}
	v, _ := strconv.ParseUint(s, 16, 32)
	return color.NRGBA{uint8(v >> 24), uint8(v >> 16), uint8(v >> 8), uint8(v)}
}

// iconColorAt returns the colour of the 32-unit icon at (x, y). rounded gives
// the background 6-unit rounded top corners, as in the SVG; the bottom band is
// square, as in the SVG. Without rounding the background fills the square
// (Apple's home screen rounds icons itself and shows transparency as black).
func iconColorAt(x, y float64, bar, edge color.NRGBA, rounded bool) (color.NRGBA, bool) {
	if x < 0 || y < 0 || x >= 32 || y >= 32 {
		return color.NRGBA{}, false
	}
	// White strokes, 2 units wide: two boxes joined by an elbow line.
	in := func(x0, y0, x1, y1 float64) bool { return x >= x0 && x < x1 && y >= y0 && y < y1 }
	box := func(x0, y0, x1, y1 float64) bool {
		return in(x0-1, y0-1, x1+1, y1+1) && !in(x0+1, y0+1, x1-1, y1-1)
	}
	if box(8, 9, 15, 14) || box(17, 15, 24, 20) || in(10.5, 14, 12.5, 18.5) || in(10.5, 16.5, 17, 18.5) {
		return color.NRGBA{255, 255, 255, 255}, true
	}
	if y >= 27 {
		return edge, true
	}
	if rounded {
		const r = 6
		cx, cy := x, y
		switch {
		case x < r && y < r:
			cx, cy = r-x, r-y
		case x > 32-r && y < r:
			cx, cy = x-(32-r), r-y
		case x < r && y > 32-r:
			cx, cy = r-x, y-(32-r)
		case x > 32-r && y > 32-r:
			cx, cy = x-(32-r), y-(32-r)
		default:
			return bar, true
		}
		if cx*cx+cy*cy > r*r {
			return color.NRGBA{}, false
		}
	}
	return bar, true
}

// IconPNG draws the favicon as a size x size PNG, with 4x4 supersampling.
func IconPNG(entries []Entry, size int, rounded bool) []byte {
	bar, edge := faviconColors(entries)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	scale := 32 / float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) * scale
					y := (float64(py) + (float64(sy)+0.5)/ss) * scale
					if c, ok := iconColorAt(x, y, bar, edge, rounded); ok {
						ca := float64(c.A) / 255
						r += float64(c.R) * ca
						g += float64(c.G) * ca
						b += float64(c.B) * ca
						a += ca
					}
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{
				uint8(r/a + 0.5), uint8(g/a + 0.5), uint8(b/a + 0.5), uint8(a/(ss*ss)*255 + 0.5),
			})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// FaviconICO returns a .ico file holding 16, 32 and 48 px PNG images.
func FaviconICO(entries []Entry) []byte {
	sizes := []int{16, 32, 48}
	imgs := make([][]byte, len(sizes))
	for i, s := range sizes {
		imgs[i] = IconPNG(entries, s, true)
	}
	var buf bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&buf, le, [3]uint16{0, 1, uint16(len(sizes))}) // reserved, type icon, count
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		buf.Write([]byte{byte(s), byte(s), 0, 0})    // width, height, palette, reserved
		_ = binary.Write(&buf, le, [2]uint16{1, 32}) // planes, bits per pixel
		_ = binary.Write(&buf, le, [2]uint32{uint32(len(imgs[i])), uint32(offset)})
		offset += len(imgs[i])
	}
	for _, b := range imgs {
		buf.Write(b)
	}
	return buf.Bytes()
}
