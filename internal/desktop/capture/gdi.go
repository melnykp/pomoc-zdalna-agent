//go:build windows

package capture

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Source to wspólny interfejs źródła obrazu (DXGI albo GDI).
type Source interface {
	// Grab czeka do timeoutMs na nową klatkę (GDI nie ma powiadomień o zmianach, więc zwraca od razu).
	Grab(timeoutMs uint32, dst []byte) (Frame, error)
	Size() (int, int)
	Close()
}

var (
	gdi32                = windows.NewLazySystemDLL("gdi32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetDC            = user32.NewProc("GetDC")
	procReleaseDC        = user32.NewProc("ReleaseDC")
	procCreateCompatDC   = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC         = gdi32.NewProc("DeleteDC")
	procCreateDIBSection = gdi32.NewProc("CreateDIBSection")
	procSelectObject     = gdi32.NewProc("SelectObject")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procBitBlt           = gdi32.NewProc("BitBlt")
)

type bitmapInfoHeader struct {
	Size          uint32
	Width, Height int32
	Planes, Bits  uint16
	Compression   uint32
	SizeImage     uint32
	XPels, YPels  int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// GDI przechwytuje prostokąt pulpitu przez BitBlt z kontekstu ekranu. Wolniejsze od DXGI, ale działa tam, gdzie
// duplikacja nie działa (niektóre sterowniki, część sesji zdalnych); nie widzi ochronionych treści.
type GDI struct {
	left, top, w, h int
	screenDC        uintptr
	memDC           uintptr
	bmp             uintptr
	old             uintptr
	bits            unsafe.Pointer
}

// OpenGDI przygotowuje przechwytywanie prostokąta pulpitu wirtualnego (współrzędne pikseli).
func OpenGDI(left, top, w, h int) (*GDI, error) {
	g := &GDI{left: left, top: top, w: w, h: h}
	g.screenDC, _, _ = procGetDC.Call(0)
	if g.screenDC == 0 {
		return nil, fmt.Errorf("GetDC(NULL) nie powiodło się")
	}
	g.memDC, _, _ = procCreateCompatDC.Call(g.screenDC)
	if g.memDC == 0 {
		g.Close()
		return nil, fmt.Errorf("CreateCompatibleDC nie powiodło się")
	}
	bi := bitmapInfoHeader{Size: uint32(unsafe.Sizeof(bitmapInfoHeader{})), Width: int32(w), Height: -int32(h), Planes: 1, Bits: 32}
	g.bmp, _, _ = procCreateDIBSection.Call(g.memDC, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&g.bits)), 0, 0)
	if g.bmp == 0 || g.bits == nil {
		g.Close()
		return nil, fmt.Errorf("CreateDIBSection nie powiodło się")
	}
	g.old, _, _ = procSelectObject.Call(g.memDC, g.bmp)
	return g, nil
}

// Size zwraca rozmiar obrazu.
func (g *GDI) Size() (int, int) { return g.w, g.h }

// Grab kopiuje bieżący obraz pulpitu (BGRA, stride = 4*w).
func (g *GDI) Grab(_ uint32, dst []byte) (Frame, error) {
	t0 := time.Now()
	const srcCopy, captureBlt = 0x00CC0020, 0x40000000
	r, _, e := procBitBlt.Call(g.memDC, 0, 0, uintptr(g.w), uintptr(g.h), g.screenDC, uintptr(g.left), uintptr(g.top), srcCopy|captureBlt)
	if r == 0 {
		return Frame{}, fmt.Errorf("BitBlt: %v", e)
	}
	n := g.w * g.h * 4
	if cap(dst) < n {
		dst = make([]byte, n)
	}
	dst = dst[:n]
	copy(dst, unsafe.Slice((*byte)(g.bits), n))
	return Frame{Width: g.w, Height: g.h, Stride: g.w * 4, Pix: dst, Updated: true, GrabCopy: time.Since(t0)}, nil
}

// Close zwalnia uchwyty GDI.
func (g *GDI) Close() {
	if g.old != 0 {
		procSelectObject.Call(g.memDC, g.old)
	}
	if g.bmp != 0 {
		procDeleteObject.Call(g.bmp)
	}
	if g.memDC != 0 {
		procDeleteDC.Call(g.memDC)
	}
	if g.screenDC != 0 {
		procReleaseDC.Call(0, g.screenDC)
	}
	g.screenDC, g.memDC, g.bmp, g.old = 0, 0, 0, 0
}
