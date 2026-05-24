// icogen converts a single source PNG into the platform-native icon
// container Vaultify needs. Stdlib only, no external deps; lives under
// tools/ so the runtime module stays lean.
//
// Output formats (-format):
//
//	ico     Windows multi-resolution .ico (PNG-in-ICO entries).
//	        Default. Use with rsrc to embed in vaultify.exe.
//	icns    macOS .icns for an .app bundle's Resources/AppIcon.icns.
//	png-set Hicolor PNG set for Linux desktops, written under -out
//	        as `<out>/<size>x<size>/apps/vaultify.png` plus a
//	        `vaultify.desktop` template at the root.
//
// Examples:
//
//	go run ./tools/icogen -format ico  -in logo.png -out vaultify.ico
//	go run ./tools/icogen -format icns -in logo.png -out Vaultify.icns
//	go run ./tools/icogen -format png-set -in logo.png -out dist/linux-icons
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
)

// icoSizes are the resolutions packed into a Windows .ico. Covers the
// common Windows shell render points (taskbar, Alt-Tab, Explorer
// thumbnails up to "Extra large" view).
var icoSizes = []int{16, 24, 32, 48, 64, 128, 256}

// linuxHicolorSizes are the standard hicolor theme rasters Linux
// desktop environments look for.
var linuxHicolorSizes = []int{16, 22, 24, 32, 48, 64, 128, 256, 512}

// icnsEntry pairs a macOS ICNS type code with the pixel size of the
// PNG payload that fills it. Sizes chosen to cover Retina (@2x) and
// non-Retina display points without inflating the file.
//
// Reference: https://en.wikipedia.org/wiki/Apple_Icon_Image_format
var icnsEntries = []struct {
	Type [4]byte
	Size int
}{
	// Match iconutil output: no 16/32/64 @1x legacy slots (ic04/icp4).
	// Those tiny rasters get picked for auth dialogs and upscale badly.
	{[4]byte{'i', 'c', '1', '1'}, 32},   // 16pt @2x
	{[4]byte{'i', 'c', '1', '2'}, 64},   // 32pt @2x
	{[4]byte{'i', 'c', '0', '7'}, 128},  // 128pt @1x
	{[4]byte{'i', 'c', '1', '3'}, 256},  // 128pt @2x
	{[4]byte{'i', 'c', '0', '8'}, 256},  // 256pt @1x
	{[4]byte{'i', 'c', '1', '4'}, 512},  // 256pt @2x
	{[4]byte{'i', 'c', '0', '9'}, 512},  // 512pt @1x
	{[4]byte{'i', 'c', '1', '0'}, 1024}, // 512pt @2x
}

func main() {
	in := flag.String("in", "", "source PNG (square recommended)")
	out := flag.String("out", "", "destination path (file for ico/icns, dir for png-set)")
	format := flag.String("format", "ico", "output format: ico | icns | png-set")
	flag.Parse()
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "icogen: -in and -out are required")
		os.Exit(2)
	}

	src, err := loadPNG(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "icogen: read %s: %v\n", *in, err)
		os.Exit(1)
	}

	switch *format {
	case "ico":
		err = generateICO(src, *out)
	case "icns":
		err = generateICNS(src, *out)
	case "png-set":
		err = generatePNGSet(src, *out)
	default:
		fmt.Fprintf(os.Stderr, "icogen: unknown -format %q (want ico|icns|png-set)\n", *format)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "icogen: %v\n", err)
		os.Exit(1)
	}
}

// generateICO scales src to the standard Windows shell sizes and packs
// each as a PNG-in-ICO entry.
func generateICO(src image.Image, out string) error {
	entries := make([]entry, 0, len(icoSizes))
	for _, sz := range icoSizes {
		payload, err := encodeScaledPNG(src, sz)
		if err != nil {
			return fmt.Errorf("ico %dpx: %w", sz, err)
		}
		entries = append(entries, entry{size: sz, payload: payload})
	}
	if err := writeICO(out, entries); err != nil {
		return fmt.Errorf("ico write %s: %w", out, err)
	}
	fmt.Printf("icogen: wrote %s with %d sizes (%v)\n", out, len(entries), icoSizes)
	return nil
}

// generateICNS writes a macOS Apple Icon Image File. Each entry is a
// PNG payload tagged with the type code macOS uses for that pixel
// size. Modern macOS (10.7+) accepts PNG inside every ic07–ic14 slot
// so we don't bother with the legacy raw-RGB+mask formats.
func generateICNS(src image.Image, out string) error {
	type chunk struct {
		typ     [4]byte
		payload []byte
	}
	var (
		chunks []chunk
		bodyLen int
	)
	sizes := make([]int, 0, len(icnsEntries))
	for _, e := range icnsEntries {
		payload, err := encodeScaledPNG(src, e.Size)
		if err != nil {
			return fmt.Errorf("icns %dpx: %w", e.Size, err)
		}
		chunks = append(chunks, chunk{typ: e.Type, payload: payload})
		bodyLen += 8 + len(payload) // 4 bytes type + 4 bytes length + payload
		sizes = append(sizes, e.Size)
	}

	// Top-level ICNS header: magic 'icns' + total file length (BE).
	totalLen := 8 + bodyLen
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte{'i', 'c', 'n', 's'}); err != nil {
		return err
	}
	if err := binary.Write(f, binary.BigEndian, uint32(totalLen)); err != nil {
		return err
	}
	for _, c := range chunks {
		if _, err := f.Write(c.typ[:]); err != nil {
			return err
		}
		if err := binary.Write(f, binary.BigEndian, uint32(8+len(c.payload))); err != nil {
			return err
		}
		if _, err := f.Write(c.payload); err != nil {
			return err
		}
	}
	fmt.Printf("icogen: wrote %s with %d retina-aware entries (%v)\n", out, len(chunks), sizes)
	return nil
}

// generatePNGSet emits the hicolor-themed PNG set Linux desktop
// environments expect, plus a vaultify.desktop template the user can
// drop into ~/.local/share/applications/. Layout:
//
//	<out>/
//	  16x16/apps/vaultify.png
//	  22x22/apps/vaultify.png
//	  ...
//	  vaultify.desktop
func generatePNGSet(src image.Image, out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, sz := range linuxHicolorSizes {
		dir := filepath.Join(out, fmt.Sprintf("%dx%d", sz, sz), "apps")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path := filepath.Join(dir, "vaultify.png")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		if err := png.Encode(f, boxResize(src, sz, sz)); err != nil {
			f.Close()
			return fmt.Errorf("png-set %dpx: %w", sz, err)
		}
		f.Close()
	}

	desktop := `[Desktop Entry]
Name=Vaultify
GenericName=Credential Remediation
Comment=Endpoint credential remediation toolkit
Exec=vaultify
Icon=vaultify
Terminal=false
Type=Application
Categories=Utility;Security;
StartupNotify=false
Keywords=secrets;credentials;security;1password;
`
	if err := os.WriteFile(filepath.Join(out, "vaultify.desktop"), []byte(desktop), 0o644); err != nil {
		return err
	}
	fmt.Printf("icogen: wrote hicolor PNG set under %s (%d sizes) + vaultify.desktop\n", out, len(linuxHicolorSizes))
	return nil
}

// encodeScaledPNG box-resizes src to size×size and PNG-encodes it.
func encodeScaledPNG(src image.Image, size int) ([]byte, error) {
	scaled := boxResize(src, size, size)
	var buf bytes.Buffer
	if err := png.Encode(&buf, scaled); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type entry struct {
	size    int
	payload []byte
}

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

// boxResize downsamples src into a w×h NRGBA image using a simple box
// filter (average of every source pixel that maps inside the target
// cell). Fast, no external dep, and visually clean for big-to-small
// shrinks like 1024→16. Upscaling falls back to nearest-neighbour but
// callers shouldn't do that for icons.
func boxResize(src image.Image, w, h int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	if sw <= 0 || sh <= 0 {
		return dst
	}

	// Pre-extract source as NRGBA once so per-cell sampling is cheap.
	srcN := image.NewNRGBA(image.Rect(0, 0, sw, sh))
	for y := 0; y < sh; y++ {
		for x := 0; x < sw; x++ {
			c := color.NRGBAModel.Convert(src.At(sb.Min.X+x, sb.Min.Y+y)).(color.NRGBA)
			off := y*srcN.Stride + x*4
			srcN.Pix[off+0] = c.R
			srcN.Pix[off+1] = c.G
			srcN.Pix[off+2] = c.B
			srcN.Pix[off+3] = c.A
		}
	}

	for dy := 0; dy < h; dy++ {
		y0 := dy * sh / h
		y1 := (dy + 1) * sh / h
		if y1 == y0 {
			y1 = y0 + 1
		}
		for dx := 0; dx < w; dx++ {
			x0 := dx * sw / w
			x1 := (dx + 1) * sw / w
			if x1 == x0 {
				x1 = x0 + 1
			}

			var rs, gs, bs, as, n uint64
			for sy := y0; sy < y1; sy++ {
				row := sy * srcN.Stride
				for sx := x0; sx < x1; sx++ {
					off := row + sx*4
					rs += uint64(srcN.Pix[off+0])
					gs += uint64(srcN.Pix[off+1])
					bs += uint64(srcN.Pix[off+2])
					as += uint64(srcN.Pix[off+3])
					n++
				}
			}
			if n == 0 {
				continue
			}
			doff := dy*dst.Stride + dx*4
			dst.Pix[doff+0] = uint8(rs / n)
			dst.Pix[doff+1] = uint8(gs / n)
			dst.Pix[doff+2] = uint8(bs / n)
			dst.Pix[doff+3] = uint8(as / n)
		}
	}
	return dst
}

// writeICO serialises entries as an ICO file with PNG payloads. ICO is
// a tiny, well-documented format: an ICONDIR (6 bytes) followed by N
// ICONDIRENTRYs (16 bytes each), then the raw payloads.
//
// Reference: https://learn.microsoft.com/en-us/previous-versions/ms997538(v=msdn.10)
func writeICO(path string, entries []entry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	const (
		dirSize   = 6
		entrySize = 16
	)
	headerLen := dirSize + entrySize*len(entries)

	if err := writeAll(f, []any{
		uint16(0), // reserved
		uint16(1), // type = icon
		uint16(len(entries)),
	}); err != nil {
		return err
	}

	offset := headerLen
	for _, e := range entries {
		w := byte(0)
		h := byte(0)
		if e.size < 256 {
			w = byte(e.size)
			h = byte(e.size)
		}
		// For PNG-in-ICO entries, planes/bpp are conventionally set to
		// (1, 32) or (0, 32). Windows ignores the values when the
		// payload is a PNG, but writing sane defaults helps inspectors.
		if err := writeAll(f, []any{
			w, h,                  // width, height (0 == 256)
			byte(0),               // colour palette count
			byte(0),               // reserved
			uint16(1),             // colour planes
			uint16(32),            // bits per pixel
			uint32(len(e.payload)),
			uint32(offset),
		}); err != nil {
			return err
		}
		offset += len(e.payload)
	}

	for _, e := range entries {
		if _, err := f.Write(e.payload); err != nil {
			return err
		}
	}
	return nil
}

// writeAll writes the supplied values in little-endian order. Any type
// supported by binary.Write (uint8/16/32, byte) is accepted.
func writeAll(w io.Writer, vals []any) error {
	for _, v := range vals {
		if err := binary.Write(w, binary.LittleEndian, v); err != nil {
			return err
		}
	}
	return nil
}
