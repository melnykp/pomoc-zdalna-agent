//go:build windows

package capture

import (
	"image"
	"image/color"
	"unsafe"
)

var (
	procGetCursorInfo = user32.NewProc("GetCursorInfo")
	procGetIconInfo   = user32.NewProc("GetIconInfo")
	procDrawIconEx    = user32.NewProc("DrawIconEx")
	procGetObjectW    = gdi32.NewProc("GetObjectW")
)

type cursorInfoT struct {
	Size   uint32
	Flags  uint32
	Cursor uintptr
	X, Y   int32
}

type iconInfoT struct {
	Icon     uint32
	HotX     uint32
	HotY     uint32
	Mask     uintptr
	ColorBmp uintptr
}

type bitmapT struct {
	Type       int32
	Width      int32
	Height     int32
	WidthBytes int32
	Planes     uint16
	BitsPixel  uint16
	Bits       uintptr
}

const (
	cursorShowing = 0x1
	diNormal      = 0x3
	maxCursorSide = 256
)

// cursorTracker śledzi kursor systemowy dla źródła GDI: położenie względem monitora przy każdej klatce, a kształt tylko
// wtedy, gdy zmienił się uchwyt kursora (rysowanie kształtu jest drogie).
type cursorTracker struct {
	handle  uintptr
	last    Pointer
	pending Pointer
	have    bool
}

// poll odczytuje kursor (GetCursorInfo) i notuje zmiany do odbioru przez take.
func (c *cursorTracker) poll(left, top int) {
	ci := cursorInfoT{Size: uint32(unsafe.Sizeof(cursorInfoT{}))}
	if r, _, _ := procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 {
		return
	}
	visible := ci.Flags&cursorShowing != 0 && ci.Cursor != 0
	x, y := int(ci.X)-left, int(ci.Y)-top
	if !c.have || x != c.last.X || y != c.last.Y || visible != c.last.Visible {
		c.last.X, c.last.Y, c.last.Visible = x, y, visible
		c.pending.Moved = true
	}
	if visible && (!c.have || ci.Cursor != c.handle) {
		if shape := renderCursorShape(ci.Cursor); shape != nil {
			c.pending.Shape = shape
		}
		c.handle = ci.Cursor
	}
	c.have = true
}

// take oddaje zebrane zmiany: zawsze pełny bieżący stan (położenie, widoczność), kształt tylko po zmianie.
func (c *cursorTracker) take() (Pointer, bool) {
	p := c.pending
	ok := p.Moved || p.Shape != nil
	c.pending = Pointer{}
	p.X, p.Y, p.Visible = c.last.X, c.last.Y, c.last.Visible
	return p, ok
}

func (c *cursorTracker) close() { *c = cursorTracker{} }

// renderCursorShape rysuje kursor dwa razy, na czarnym i na białym tle, i z różnicy odzyskuje kanał alfa
// (klasyczna metoda dla kursorów, które GDI rysuje bez alfy): kolor na czarnym = c*a, na białym = c*a + 255*(1-a).
func renderCursorShape(hCursor uintptr) *PointerShape {
	var ii iconInfoT
	if r, _, _ := procGetIconInfo.Call(hCursor, uintptr(unsafe.Pointer(&ii))); r == 0 {
		return nil
	}
	defer func() {
		if ii.Mask != 0 {
			procDeleteObject.Call(ii.Mask)
		}
		if ii.ColorBmp != 0 {
			procDeleteObject.Call(ii.ColorBmp)
		}
	}()
	var bm bitmapT
	src := ii.ColorBmp
	if src == 0 {
		src = ii.Mask
	}
	if r, _, _ := procGetObjectW.Call(src, unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm))); r == 0 {
		return nil
	}
	w, h := int(bm.Width), int(bm.Height)
	if ii.ColorBmp == 0 {
		h /= 2 // kursor monochromatyczny: maska AND nad maską XOR
	}
	if w <= 0 || h <= 0 || w > maxCursorSide || h > maxCursorSide {
		return nil
	}

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil
	}
	defer procReleaseDC.Call(0, screenDC)
	memDC, _, _ := procCreateCompatDC.Call(screenDC)
	if memDC == 0 {
		return nil
	}
	defer procDeleteDC.Call(memDC)
	bi := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(w), Height: -int32(h), Planes: 1, Bits: 32}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(memDC, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return nil
	}
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, old)

	n := w * h * 4
	pix := unsafe.Slice((*byte)(bits), n)
	draw := func(fill byte) []byte {
		for i := range pix {
			pix[i] = fill
		}
		procDrawIconEx.Call(memDC, 0, 0, hCursor, uintptr(w), uintptr(h), 0, 0, diNormal)
		return append([]byte(nil), pix...)
	}
	onBlack := draw(0x00)
	onWhite := draw(0xFF)
	return &PointerShape{Image: alphaFromBackgrounds(onBlack, onWhite, w, h), HotX: int(ii.HotX), HotY: int(ii.HotY)}
}

// alphaFromBackgrounds odzyskuje obraz NRGBA z dwóch rysunków tego samego kursora (BGRA) na czarnym i białym tle.
func alphaFromBackgrounds(onBlack, onWhite []byte, w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		bB, bG, bR := int(onBlack[i*4]), int(onBlack[i*4+1]), int(onBlack[i*4+2])
		wB, wG, wR := int(onWhite[i*4]), int(onWhite[i*4+1]), int(onWhite[i*4+2])
		diff := ((wB - bB) + (wG - bG) + (wR - bR)) / 3 // = 255*(1-a)
		a := 255 - diff
		if a <= 0 {
			continue // w pełni przezroczysty
		}
		if a > 255 {
			a = 255
		}
		un := func(c int) uint8 { // kolor bez wpływu alfy
			v := c * 255 / a
			if v > 255 {
				v = 255
			}
			return uint8(v)
		}
		img.SetNRGBA(i%w, i/w, color.NRGBA{R: un(bR), G: un(bG), B: un(bB), A: uint8(a)})
	}
	return img
}
