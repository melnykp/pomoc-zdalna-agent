//go:build windows

package capture

import (
	"image"
	"image/color"
	"unsafe"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// slotDuplPointerShape to IDXGIOutputDuplication::GetFramePointerShape (dxgi1_2.h).
const slotDuplPointerShape = 11

// Rodzaje kształtu kursora z DXGI_OUTDUPL_POINTER_SHAPE_TYPE.
const (
	pointerMonochrome  = 1
	pointerColor       = 2
	pointerMaskedColor = 4
)

type pointerShapeInfo struct {
	Type          uint32
	Width, Height uint32
	Pitch         uint32
	HotX, HotY    int32
}

// Pointer to stan kursora z ostatniej klatki duplikacji: położenie względem lewego górnego rogu monitora i, gdy się
// zmienił, nowy kształt. DXGI nie wkłada kursora do obrazu, więc idzie on do widza osobnym strumieniem.
type Pointer struct {
	X, Y    int
	Visible bool
	// Moved mówi, że od poprzedniego odczytu system zgłosił nowe położenie lub widoczność.
	Moved bool
	// Shape to nowy kształt (nil, gdy bez zmian). Obraz jest w RGBA z punktem zaczepienia HotX, HotY.
	Shape *PointerShape
}

// PointerShape to kształt kursora przeliczony na zwykły obraz RGBA.
type PointerShape struct {
	Image      *image.NRGBA
	HotX, HotY int
}

// notePointer zapisuje położenie kursora z nagłówka klatki i pobiera kształt, gdy system zgłosił jego zmianę.
// Wołane po udanym AcquireNextFrame, przed ReleaseFrame.
func (d *Duplicator) notePointer(info *frameInfo) {
	if info.LastMouseUpdate != 0 {
		vis := info.PointerVisible != 0
		if int(info.PointerX) != d.ptr.X || int(info.PointerY) != d.ptr.Y || vis != d.ptr.Visible {
			d.ptr.X, d.ptr.Y, d.ptr.Visible = int(info.PointerX), int(info.PointerY), vis
			d.ptr.Moved = true
		}
	}
	if info.PointerShapeSize == 0 {
		return
	}
	if cap(d.ptrBuf) < int(info.PointerShapeSize) {
		d.ptrBuf = make([]byte, info.PointerShapeSize)
	}
	buf := d.ptrBuf[:info.PointerShapeSize]
	var need uint32
	var si pointerShapeInfo
	h := com.Call(d.dupl, slotDuplPointerShape, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&si)))
	if h.Failed() {
		return
	}
	if img := decodePointerShape(si, buf[:need]); img != nil {
		d.ptr.Shape = &PointerShape{Image: img, HotX: int(si.HotX), HotY: int(si.HotY)}
	}
}

// Pointer zwraca zebrane zmiany kursora od poprzedniego wywołania i kasuje znaczniki zmian. ok mówi, czy coś się zmieniło.
func (d *Duplicator) Pointer() (p Pointer, ok bool) {
	p = d.ptr
	ok = p.Moved || p.Shape != nil
	d.ptr.Moved, d.ptr.Shape = false, nil
	return p, ok
}

// decodePointerShape zamienia surowy kształt DXGI na obraz RGBA. Kolor: BGRA wprost. Kolor z maską: bit maski 1 oznacza
// piksel XOR z ekranem (rysujemy jako półprzezroczystą odwrotność: dokładny XOR nie da się odtworzyć bez obrazu pod kursorem).
// Monochromatyczny: połowa górna to maska AND, dolna XOR; AND=1,XOR=0 przezroczysty, AND=0 kolor z XOR (czarny/biały),
// AND=1,XOR=1 odwrócenie (rysujemy jako szary półprzezroczysty).
func decodePointerShape(si pointerShapeInfo, raw []byte) *image.NRGBA {
	w, h, pitch := int(si.Width), int(si.Height), int(si.Pitch)
	if w <= 0 || h <= 0 || w > 512 || h > 1024 {
		return nil
	}
	switch si.Type {
	case pointerColor, pointerMaskedColor:
		if len(raw) < pitch*h || pitch < w*4 {
			return nil
		}
		img := image.NewNRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			row := raw[y*pitch : y*pitch+w*4]
			for x := 0; x < w; x++ {
				b, g, r, a := row[x*4], row[x*4+1], row[x*4+2], row[x*4+3]
				if si.Type == pointerMaskedColor {
					if a != 0 { // bit maski: XOR z ekranem
						img.SetNRGBA(x, y, color.NRGBA{R: 255 - r, G: 255 - g, B: 255 - b, A: 160})
					} else {
						img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: 255})
					}
					continue
				}
				img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
			}
		}
		return img
	case pointerMonochrome:
		hh := h / 2
		if hh <= 0 || len(raw) < pitch*h || pitch*8 < w {
			return nil
		}
		img := image.NewNRGBA(image.Rect(0, 0, w, hh))
		for y := 0; y < hh; y++ {
			andRow := raw[y*pitch : (y+1)*pitch]
			xorRow := raw[(y+hh)*pitch : (y+hh+1)*pitch]
			for x := 0; x < w; x++ {
				bit := byte(0x80 >> (x % 8))
				and := andRow[x/8]&bit != 0
				xor := xorRow[x/8]&bit != 0
				switch {
				case and && !xor:
					img.SetNRGBA(x, y, color.NRGBA{})
				case !and && !xor:
					img.SetNRGBA(x, y, color.NRGBA{A: 255})
				case !and && xor:
					img.SetNRGBA(x, y, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
				default:
					img.SetNRGBA(x, y, color.NRGBA{R: 128, G: 128, B: 128, A: 160})
				}
			}
		}
		return img
	}
	return nil
}
