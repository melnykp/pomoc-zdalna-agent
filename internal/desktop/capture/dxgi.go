//go:build windows

// Package capture przechwytuje ekran: DXGI Desktop Duplication (główna droga) i GDI (zapas).
package capture

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// Sloty vtable sprawdzone z nagłówków SDK (dxgi.h, dxgi1_2.h, d3d11.h).
const (
	slotFactoryEnumAdapters1 = 12
	slotAdapterEnumOutputs   = 7
	slotAdapterGetDesc1      = 10
	slotOutputGetDesc        = 7
	slotOutput1Duplicate     = 22
	slotDuplGetDesc          = 7
	slotDuplAcquire          = 8
	slotDuplDirtyRects       = 9
	slotDuplMoveRects        = 10
	slotDuplReleaseFrame     = 14
	slotDeviceCreateTexture2 = 5
	slotTexGetDesc           = 10
	slotCtxMap               = 14
	slotCtxUnmap             = 15
	slotCtxCopyResource      = 47
)

var (
	iidFactory1   = com.MustGUID(0x770aae78, 0xf26f, 0x4dba, 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87)
	iidOutput1    = com.MustGUID(0x00cddea8, 0x939b, 0x4b83, 0xa3, 0x40, 0xa6, 0x85, 0x22, 0x66, 0x66, 0xcc)
	iidTexture2D  = com.MustGUID(0x6f15aaf2, 0xd208, 0x4e89, 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c)
	dxgi          = windows.NewLazySystemDLL("dxgi.dll")
	d3d11         = windows.NewLazySystemDLL("d3d11.dll")
	procFactory1  = dxgi.NewProc("CreateDXGIFactory1")
	procCreateDev = d3d11.NewProc("D3D11CreateDevice")
)

// Znane HRESULT-y DXGI.
const (
	dxgiErrorWaitTimeout       com.HRESULT = 0x887A0027
	dxgiErrorAccessLost        com.HRESULT = 0x887A0026
	dxgiErrorNotCurrentlyAvail com.HRESULT = 0x887A0022
	dxgiErrorUnsupported       com.HRESULT = 0x887A0004
	dxgiErrorDeviceRemoved     com.HRESULT = 0x887A0005
	dxgiErrorNotFound          com.HRESULT = 0x887A0002
	eAccessDenied              com.HRESULT = 0x80070005
	dxgiErrorSessionDisc       com.HRESULT = 0x887A0028
)

// ErrTimeout oznacza brak zmian na ekranie w zadanym czasie (to nie jest błąd).
var ErrTimeout = errors.New("brak nowej klatki")

// ErrAccessLost oznacza utratę dostępu do duplikacji (zmiana rozdzielczości, ekran blokady, UAC); trzeba otworzyć na nowo.
var ErrAccessLost = errors.New("utracono dostęp do duplikacji pulpitu")

// Display opisuje jeden monitor widziany przez DXGI.
type Display struct {
	AdapterIdx  int
	OutputIdx   int
	AdapterName string
	VendorID    uint32
	DeviceName  string
	Left, Top   int32
	Right, Bot  int32
	Attached    bool
	Rotation    uint32
}

func (d Display) Width() int  { return int(d.Right - d.Left) }
func (d Display) Height() int { return int(d.Bot - d.Top) }

type adapterDesc1 struct {
	Description [128]uint16
	VendorID    uint32
	DeviceID    uint32
	SubSysID    uint32
	Revision    uint32
	DedVideo    uintptr
	DedSystem   uintptr
	SharedSys   uintptr
	LUID        windows.LUID
	Flags       uint32
}

type outputDesc struct {
	DeviceName [32]uint16
	Left, Top  int32
	Right, Bot int32
	Attached   int32
	Rotation   uint32
	Monitor    uintptr
}

type texDesc struct {
	Width, Height, MipLevels, ArraySize uint32
	Format                              uint32
	SampleCount, SampleQuality          uint32
	Usage, BindFlags, CPUAccess, Misc   uint32
}

type frameInfo struct {
	LastPresent      int64
	LastMouseUpdate  int64
	AccumulatedFrame uint32
	RectsCoalesced   int32
	ProtectedMasked  int32
	PointerX         int32
	PointerY         int32
	PointerVisible   int32
	TotalMetadata    uint32
	PointerShapeSize uint32
}

type mappedSubresource struct {
	Data       unsafe.Pointer
	RowPitch   uint32
	DepthPitch uint32
}

type duplDesc struct {
	Width, Height      uint32
	RefreshNum, RefDen uint32
	Format             uint32
	Scanline, Scaling  uint32
	Rotation           uint32
	InSystemMemory     int32
}

// Rect to prostokąt zmian w pikselach.
type Rect struct{ Left, Top, Right, Bottom int32 }

func createFactory() (*com.Object, error) {
	var f *com.Object
	r, _, _ := procFactory1.Call(uintptr(unsafe.Pointer(&iidFactory1)), uintptr(unsafe.Pointer(&f)))
	if err := com.Check("CreateDXGIFactory1", com.HRESULT(uint32(r))); err != nil {
		return nil, err
	}
	return f, nil
}

// Adapter opisuje kartę graficzną DXGI.
type Adapter struct {
	Index     int
	Name      string
	VendorID  uint32
	Flags     uint32
	VideoMemB uint64
}

// ListAdapters wylicza karty graficzne widoczne dla DXGI.
func ListAdapters() ([]Adapter, error) {
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer com.Release(f)
	var out []Adapter
	for ai := 0; ; ai++ {
		var ad *com.Object
		h := com.Call(f, slotFactoryEnumAdapters1, uintptr(ai), uintptr(unsafe.Pointer(&ad)))
		if h == dxgiErrorNotFound {
			break
		}
		if h.Failed() {
			return out, com.Check("EnumAdapters1", h)
		}
		var d adapterDesc1
		com.Call(ad, slotAdapterGetDesc1, uintptr(unsafe.Pointer(&d)))
		out = append(out, Adapter{Index: ai, Name: windows.UTF16ToString(d.Description[:]), VendorID: d.VendorID, Flags: d.Flags, VideoMemB: uint64(d.DedVideo)})
		com.Release(ad)
	}
	return out, nil
}

// CreateDevice tworzy urządzenie D3D11 na karcie o danym indeksie DXGI (flags: D3D11_CREATE_DEVICE_*).
func CreateDevice(adapterIdx int, flags uint32) (dev, ctx *com.Object, err error) {
	f, err := createFactory()
	if err != nil {
		return nil, nil, err
	}
	defer com.Release(f)
	var ad *com.Object
	if err := com.Check("EnumAdapters1", com.Call(f, slotFactoryEnumAdapters1, uintptr(adapterIdx), uintptr(unsafe.Pointer(&ad)))); err != nil {
		return nil, nil, err
	}
	defer com.Release(ad)
	var fl uint32
	r, _, _ := procCreateDev.Call(uintptr(unsafe.Pointer(ad)), 0, 0, uintptr(flags), 0, 0, 7,
		uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(&fl)), uintptr(unsafe.Pointer(&ctx)))
	if err := com.Check("D3D11CreateDevice", com.HRESULT(uint32(r))); err != nil {
		return nil, nil, err
	}
	return dev, ctx, nil
}

// ListDisplays wylicza wszystkie wyjścia (monitory) na wszystkich kartach DXGI.
func ListDisplays() ([]Display, error) {
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer com.Release(f)
	var out []Display
	for ai := 0; ; ai++ {
		var ad *com.Object
		h := com.Call(f, slotFactoryEnumAdapters1, uintptr(ai), uintptr(unsafe.Pointer(&ad)))
		if h == dxgiErrorNotFound {
			break
		}
		if h.Failed() {
			return out, com.Check("EnumAdapters1", h)
		}
		var ades adapterDesc1
		com.Call(ad, slotAdapterGetDesc1, uintptr(unsafe.Pointer(&ades)))
		name := windows.UTF16ToString(ades.Description[:])
		for oi := 0; ; oi++ {
			var op *com.Object
			h := com.Call(ad, slotAdapterEnumOutputs, uintptr(oi), uintptr(unsafe.Pointer(&op)))
			if h == dxgiErrorNotFound {
				break
			}
			if h.Failed() {
				break
			}
			var od outputDesc
			com.Call(op, slotOutputGetDesc, uintptr(unsafe.Pointer(&od)))
			out = append(out, Display{
				AdapterIdx: ai, OutputIdx: oi, AdapterName: name, VendorID: ades.VendorID,
				DeviceName: windows.UTF16ToString(od.DeviceName[:]),
				Left:       od.Left, Top: od.Top, Right: od.Right, Bot: od.Bot,
				Attached: od.Attached != 0, Rotation: od.Rotation,
			})
			com.Release(op)
		}
		com.Release(ad)
	}
	return out, nil
}

// Frame to klatka pulpitu w BGRA (4 bajty na piksel), ważna do następnego wywołania Grab.
type Frame struct {
	Width, Height int
	Stride        int
	Pix           []byte
	Dirty         []Rect        // prostokąty zmian względem poprzedniej klatki (może być puste)
	Updated       bool          // false: tylko kursor się zmienił
	PresentQPC    int64         // QPC chwili ostatniego wyświetlenia zmiany na ekranie (LastPresentTime)
	Accumulated   uint32        // ile aktualizacji pulpitu zebrano w tej klatce (>1: poprzednie nie zostały odebrane na czas)
	GrabCopy      time.Duration // czas kopiowania klatki z GPU do pamięci (CopyResource + Map + memcpy)
}

// Duplicator przechwytuje jedno wyjście DXGI.
type Duplicator struct {
	Display  Display
	device   *com.Object
	ctx      *com.Object
	dupl     *com.Object
	staging  *com.Object
	w, h     int
	dirty    []Rect
	dirtyBuf []byte
	shared   bool // urządzenie D3D11 należy do wołającego
	ptr      Pointer
	ptrBuf   []byte
}

// OpenDuplicator otwiera duplikację wskazanego monitora.
func OpenDuplicator(d Display) (*Duplicator, error) {
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer com.Release(f)
	var ad *com.Object
	if err := com.Check("EnumAdapters1", com.Call(f, slotFactoryEnumAdapters1, uintptr(d.AdapterIdx), uintptr(unsafe.Pointer(&ad)))); err != nil {
		return nil, err
	}
	defer com.Release(ad)
	var op *com.Object
	if err := com.Check("EnumOutputs", com.Call(ad, slotAdapterEnumOutputs, uintptr(d.OutputIdx), uintptr(unsafe.Pointer(&op)))); err != nil {
		return nil, err
	}
	defer com.Release(op)
	op1, err := com.QueryInterface(op, &iidOutput1)
	if err != nil {
		return nil, fmt.Errorf("IDXGIOutput1: %w", err)
	}
	defer com.Release(op1)

	var dev, ctx *com.Object
	var fl uint32
	// D3D_DRIVER_TYPE_UNKNOWN (0) wymagane przy jawnej karcie; BGRA_SUPPORT (0x20); SDK 7.
	r, _, _ := procCreateDev.Call(uintptr(unsafe.Pointer(ad)), 0, 0, 0x20, 0, 0, 7,
		uintptr(unsafe.Pointer(&dev)), uintptr(unsafe.Pointer(&fl)), uintptr(unsafe.Pointer(&ctx)))
	if err := com.Check("D3D11CreateDevice", com.HRESULT(uint32(r))); err != nil {
		return nil, err
	}
	var dupl *com.Object
	h := com.Call(op1, slotOutput1Duplicate, uintptr(unsafe.Pointer(dev)), uintptr(unsafe.Pointer(&dupl)))
	if h.Failed() {
		com.Release(ctx)
		com.Release(dev)
		return nil, fmt.Errorf("DuplicateOutput: %w", h)
	}
	var dd duplDesc
	com.Call(dupl, slotDuplGetDesc, uintptr(unsafe.Pointer(&dd)))
	return &Duplicator{Display: d, device: dev, ctx: ctx, dupl: dupl, w: int(dd.Width), h: int(dd.Height)}, nil
}

// Size zwraca rozmiar obrazu w pikselach.
func (d *Duplicator) Size() (int, int) { return d.w, d.h }

// Close zwalnia zasoby (urządzenie współdzielone, z OpenDuplicatorOn, zostaje właścicielowi).
func (d *Duplicator) Close() {
	com.Release(d.staging)
	com.Release(d.dupl)
	if !d.shared {
		com.Release(d.ctx)
		com.Release(d.device)
	}
	d.staging, d.dupl, d.ctx, d.device = nil, nil, nil, nil
}

func (d *Duplicator) ensureStaging(src *com.Object) error {
	var sd texDesc
	com.Call(src, slotTexGetDesc, uintptr(unsafe.Pointer(&sd)))
	if d.staging != nil && int(sd.Width) == d.w && int(sd.Height) == d.h {
		return nil
	}
	com.Release(d.staging)
	d.staging = nil
	desc := texDesc{
		Width: sd.Width, Height: sd.Height, MipLevels: 1, ArraySize: 1, Format: sd.Format,
		SampleCount: 1, Usage: 3 /*STAGING*/, CPUAccess: 0x20000, /*READ*/
	}
	var tex *com.Object
	if err := com.Check("CreateTexture2D(staging)", com.Call(d.device, slotDeviceCreateTexture2,
		uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&tex)))); err != nil {
		return err
	}
	d.staging = tex
	d.w, d.h = int(sd.Width), int(sd.Height)
	return nil
}

// Grab czeka do timeoutMs na nową klatkę i kopiuje ją do pamięci procesu (readback przez teksturę pomostową).
// dst może być użyte ponownie (jeśli ma dość miejsca). Zwraca ErrTimeout, gdy ekran się nie zmienił.
func (d *Duplicator) Grab(timeoutMs uint32, dst []byte) (Frame, error) {
	var info frameInfo
	var res *com.Object
	h := com.Call(d.dupl, slotDuplAcquire, uintptr(timeoutMs), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&res)))
	switch {
	case h == dxgiErrorWaitTimeout:
		return Frame{}, ErrTimeout
	case h == dxgiErrorAccessLost:
		return Frame{}, fmt.Errorf("%w: %v", ErrAccessLost, h)
	case h == eAccessDenied:
		return Frame{}, fmt.Errorf("%w (E_ACCESSDENIED, pulpit bezpieczny?): %v", ErrAccessLost, h)
	case h.Failed():
		return Frame{}, fmt.Errorf("AcquireNextFrame: %w", h)
	}
	defer func() {
		com.Release(res)
		com.Call(d.dupl, slotDuplReleaseFrame)
	}()
	d.notePointer(&info)
	if info.LastPresent == 0 {
		// Zmienił się tylko kursor.
		return Frame{Updated: false}, ErrTimeout
	}
	copyStart := time.Now()
	tex, err := com.QueryInterface(res, &iidTexture2D)
	if err != nil {
		return Frame{}, err
	}
	defer com.Release(tex)
	if err := d.ensureStaging(tex); err != nil {
		return Frame{}, err
	}
	com.Call(d.ctx, slotCtxCopyResource, uintptr(unsafe.Pointer(d.staging)), uintptr(unsafe.Pointer(tex)))

	// Prostokąty zmian (do statystyk i do przyszłego kodowania różnicowego).
	d.dirty = d.dirty[:0]
	if info.TotalMetadata > 0 {
		if cap(d.dirtyBuf) < int(info.TotalMetadata) {
			d.dirtyBuf = make([]byte, info.TotalMetadata)
		}
		var need uint32
		hh := com.Call(d.dupl, slotDuplDirtyRects, uintptr(len(d.dirtyBuf)), uintptr(unsafe.Pointer(&d.dirtyBuf[0])), uintptr(unsafe.Pointer(&need)))
		if !hh.Failed() && need > 0 {
			n := int(need) / int(unsafe.Sizeof(Rect{}))
			d.dirty = append(d.dirty, unsafe.Slice((*Rect)(unsafe.Pointer(&d.dirtyBuf[0])), n)...)
		}
	}

	var ms mappedSubresource
	if err := com.Check("Map", com.Call(d.ctx, slotCtxMap, uintptr(unsafe.Pointer(d.staging)), 0, 1 /*READ*/, 0, uintptr(unsafe.Pointer(&ms)))); err != nil {
		return Frame{}, err
	}
	need := int(ms.RowPitch) * d.h
	if cap(dst) < need {
		dst = make([]byte, need)
	}
	dst = dst[:need]
	copy(dst, unsafe.Slice((*byte)(ms.Data), need))
	com.Call(d.ctx, slotCtxUnmap, uintptr(unsafe.Pointer(d.staging)), 0)
	return Frame{Width: d.w, Height: d.h, Stride: int(ms.RowPitch), Pix: dst, Dirty: d.dirty, Updated: true,
		PresentQPC: info.LastPresent, Accumulated: info.AccumulatedFrame, GrabCopy: time.Since(copyStart)}, nil
}
