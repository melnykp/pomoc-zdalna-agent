//go:build windows

package capture

import (
	"fmt"
	"unsafe"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// Sloty vtable sprawdzone z nagłówka d3d11.h (SDK 10.0.26100).
const (
	slotVDevCreateVP        = 4
	slotVDevCreateInputView = 8
	slotVDevCreateOutView   = 9
	slotVDevCreateEnum      = 10
	slotVCtxSetOutTargetRct = 13
	slotVCtxSetOutColorSp   = 15
	slotVCtxSetStrColorSp   = 28
	slotVCtxSetStrSrcRect   = 30
	slotVCtxSetStrDstRect   = 31
	slotVCtxSetStrAutoProc  = 37
	slotVCtxBlt             = 53
	slotCtxCopySubresource  = 46
)

var (
	iidVideoDevice  = com.MustGUID(0x10EC4D5B, 0x975A, 0x4689, 0xB9, 0xE4, 0xD0, 0xAA, 0xC3, 0x0F, 0xE3, 0x33)
	iidVideoContext = com.MustGUID(0x61F21C45, 0x3C0E, 0x4a74, 0x9C, 0xEA, 0x67, 0x10, 0x0D, 0x9A, 0xD5, 0xE4)
	iidMultithread  = com.MustGUID(0x9B7E4E00, 0x342C, 0x4106, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0)
)

const (
	dxgiFormatNV12  = 103
	d3dBindRTSRV    = 0x20 | 0x08 // RENDER_TARGET | SHADER_RESOURCE
	vpDimTexture2D  = 1
	vpColorBT709Lim = 1<<2 | 1<<4 // YCbCr_Matrix=BT.709, Nominal_Range=16-235 (pola bitowe D3D11_VIDEO_PROCESSOR_COLOR_SPACE)
)

type vpContentDesc struct {
	InputFrameFormat       uint32
	InRateNum, InRateDen   uint32
	InW, InH               uint32
	OutRateNum, OutRateDen uint32
	OutW, OutH             uint32
	Usage                  uint32
}

type vpInputViewDesc struct {
	FourCC, ViewDimension, MipSlice, ArraySlice uint32
}

type vpOutputViewDesc struct {
	ViewDimension uint32
	_             [12]byte // unia: Texture2D / Texture2DArray
}

type vpStream struct {
	Enable, OutputIndex, InputFrameOrField, PastFrames, FutureFrames uint32
	PastSurfaces                                                     uintptr
	InputSurface                                                     *com.Object
	FutureSurfaces                                                   uintptr
	PastSurfacesRight                                                uintptr
	InputSurfaceRight                                                *com.Object
	FutureSurfacesRight                                              uintptr
}

type rectI32 struct{ L, T, R, B int32 }

// EnableMultithread włącza ochronę wielowątkową urządzenia D3D11 (wymagana, gdy współdzielą je Media Foundation i my).
func EnableMultithread(dev *com.Object) {
	if mt, err := com.QueryInterface(dev, &iidMultithread); err == nil {
		com.Call(mt, 5, 1) // SetMultithreadProtected(TRUE)
		com.Release(mt)
	}
}

// VideoProc konwertuje teksturę BGRA pulpitu na teksturę NV12 na GPU (ID3D11VideoProcessor) z przycięciem do w x h
// od lewego górnego rogu. Procesor nie dotyka pikseli; wynik trafia prosto do kodera sprzętowego.
type VideoProc struct {
	dev, ctx   *com.Object
	vdev, vctx *com.Object
	enum, vp   *com.Object
	srcW, srcH int
	W, H       int
	Tex        []*com.Object // tekstury wyjściowe NV12 (pierścień)
	views      []*com.Object
	pos        int
	// CacheInput: nie twórz widoku wejściowego przy każdej klatce, gdy tekstura wejściowa się nie zmienia.
	CacheInput bool
	FlushEach  bool // Flush po każdej konwersji
	cachedSrc  *com.Object
	cachedView *com.Object
}

// NewVideoProc tworzy procesor wideo na urządzeniu dev (z flagą VIDEO_SUPPORT) i n tekstur wyjściowych NV12.
func NewVideoProc(dev, ctx *com.Object, srcW, srcH, w, h, fps, n int) (*VideoProc, error) {
	v := &VideoProc{dev: dev, ctx: ctx, srcW: srcW, srcH: srcH, W: w, H: h}
	var err error
	if v.vdev, err = com.QueryInterface(dev, &iidVideoDevice); err != nil {
		return nil, fmt.Errorf("ID3D11VideoDevice: %w", err)
	}
	if v.vctx, err = com.QueryInterface(ctx, &iidVideoContext); err != nil {
		v.Close()
		return nil, fmt.Errorf("ID3D11VideoContext: %w", err)
	}
	cd := vpContentDesc{InRateNum: uint32(fps), InRateDen: 1, InW: uint32(srcW), InH: uint32(srcH), OutRateNum: uint32(fps), OutRateDen: 1, OutW: uint32(w), OutH: uint32(h), Usage: 1}
	if err := com.Check("CreateVideoProcessorEnumerator", com.Call(v.vdev, slotVDevCreateEnum, uintptr(unsafe.Pointer(&cd)), uintptr(unsafe.Pointer(&v.enum)))); err != nil {
		v.Close()
		return nil, err
	}
	if err := com.Check("CreateVideoProcessor", com.Call(v.vdev, slotVDevCreateVP, uintptr(unsafe.Pointer(v.enum)), 0, uintptr(unsafe.Pointer(&v.vp)))); err != nil {
		v.Close()
		return nil, err
	}
	src := rectI32{0, 0, int32(w), int32(h)}
	com.Call(v.vctx, slotVCtxSetStrSrcRect, uintptr(unsafe.Pointer(v.vp)), 0, 1, uintptr(unsafe.Pointer(&src)))
	com.Call(v.vctx, slotVCtxSetStrDstRect, uintptr(unsafe.Pointer(v.vp)), 0, 1, uintptr(unsafe.Pointer(&src)))
	com.Call(v.vctx, slotVCtxSetOutTargetRct, uintptr(unsafe.Pointer(v.vp)), 1, uintptr(unsafe.Pointer(&src)))
	var inCS, outCS uint32 = 0, vpColorBT709Lim // wejście RGB pełny zakres; wyjście YCbCr BT.709 16–235
	com.Call(v.vctx, slotVCtxSetStrColorSp, uintptr(unsafe.Pointer(v.vp)), 0, uintptr(unsafe.Pointer(&inCS)))
	com.Call(v.vctx, slotVCtxSetOutColorSp, uintptr(unsafe.Pointer(v.vp)), uintptr(unsafe.Pointer(&outCS)))
	com.Call(v.vctx, slotVCtxSetStrAutoProc, uintptr(unsafe.Pointer(v.vp)), 0, 0) // bez automatycznych filtrów

	for i := 0; i < n; i++ {
		desc := texDesc{Width: uint32(w), Height: uint32(h), MipLevels: 1, ArraySize: 1, Format: dxgiFormatNV12, SampleCount: 1, BindFlags: d3dBindRTSRV}
		var tex, view *com.Object
		if err := com.Check("CreateTexture2D(NV12)", com.Call(dev, slotDeviceCreateTexture2, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&tex)))); err != nil {
			v.Close()
			return nil, err
		}
		v.Tex = append(v.Tex, tex)
		ov := vpOutputViewDesc{ViewDimension: vpDimTexture2D}
		if err := com.Check("CreateVideoProcessorOutputView", com.Call(v.vdev, slotVDevCreateOutView, uintptr(unsafe.Pointer(tex)), uintptr(unsafe.Pointer(v.enum)), uintptr(unsafe.Pointer(&ov)), uintptr(unsafe.Pointer(&view)))); err != nil {
			v.Close()
			return nil, err
		}
		v.views = append(v.views, view)
	}
	return v, nil
}

// Convert zamienia teksturę pulpitu BGRA (src) na kolejną teksturę wyjściową NV12 i zwraca jej indeks w Tex.
// Praca GPU jest kolejkowana; kolejność względem kodera zapewnia wspólne urządzenie.
func (v *VideoProc) Convert(src *com.Object) (int, error) {
	var inView *com.Object
	if v.CacheInput && src == v.cachedSrc && v.cachedView != nil {
		inView = v.cachedView // ta sama tekstura wejściowa: widok tworzymy raz (tryb syntetyczny)
	} else {
		iv := vpInputViewDesc{ViewDimension: vpDimTexture2D}
		if err := com.Check("CreateVideoProcessorInputView", com.Call(v.vdev, slotVDevCreateInputView, uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(v.enum)), uintptr(unsafe.Pointer(&iv)), uintptr(unsafe.Pointer(&inView)))); err != nil {
			return 0, err
		}
		if v.CacheInput {
			com.Release(v.cachedView)
			v.cachedSrc, v.cachedView = src, inView
		} else {
			defer com.Release(inView)
		}
	}
	st := vpStream{Enable: 1, InputSurface: inView}
	idx := v.pos
	v.pos = (v.pos + 1) % len(v.Tex)
	if err := com.Check("VideoProcessorBlt", com.Call(v.vctx, slotVCtxBlt, uintptr(unsafe.Pointer(v.vp)), uintptr(unsafe.Pointer(v.views[idx])), 0, 1, uintptr(unsafe.Pointer(&st)))); err != nil {
		return 0, err
	}
	if v.FlushEach {
		com.Call(v.ctx, 111) // ID3D11DeviceContext::Flush: wypchnij kolejkę poleceń, żeby sterownik nie gromadził ich w pamięci
	}
	return idx, nil
}

// SetSourceOrigin przesuwa przycięcie źródła: kolejna konwersja zabierze wycinek W x H od (x, y) tekstury wejściowej.
func (v *VideoProc) SetSourceOrigin(x, y int) {
	src := rectI32{int32(x), int32(y), int32(x + v.W), int32(y + v.H)}
	com.Call(v.vctx, slotVCtxSetStrSrcRect, uintptr(unsafe.Pointer(v.vp)), 0, 1, uintptr(unsafe.Pointer(&src)))
}

// CopyToDefault kopiuje teksturę src do nowej tekstury domyślnej (GPU-GPU), do wielokrotnego użycia jako źródło
// syntetycznego obrazu bez zależności od zmian na ekranie.
func CopyToDefault(dev, ctx, src *com.Object) (*com.Object, error) {
	var sd texDesc
	com.Call(src, slotTexGetDesc, uintptr(unsafe.Pointer(&sd)))
	desc := sd // te same flagi wiązania co tekstura duplikacji, żeby procesor wideo przyjął ją jako wejście
	desc.Usage, desc.CPUAccess, desc.Misc = 0, 0, 0
	var tex *com.Object
	if err := com.Check("CreateTexture2D(snapshot)", com.Call(dev, slotDeviceCreateTexture2, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&tex)))); err != nil {
		return nil, err
	}
	com.Call(ctx, slotCtxCopyResource, uintptr(unsafe.Pointer(tex)), uintptr(unsafe.Pointer(src)))
	return tex, nil
}

// Last zwraca indeks ostatnio wypełnionej tekstury wyjściowej.
func (v *VideoProc) Last() int { return (v.pos + len(v.Tex) - 1) % len(v.Tex) }

// Close zwalnia zasoby.
func (v *VideoProc) Close() {
	com.Release(v.cachedView)
	for _, x := range v.views {
		com.Release(x)
	}
	for _, x := range v.Tex {
		com.Release(x)
	}
	com.Release(v.vp)
	com.Release(v.enum)
	com.Release(v.vctx)
	com.Release(v.vdev)
	*v = VideoProc{}
}

// Probe odczytuje z teksturki BGRA mały prostokąt (np. latarnię) bez kopiowania całego obrazu.
type Probe struct {
	dev, ctx *com.Object
	stage    *com.Object
	W, H     int
}

// NewProbe tworzy teksturę pomostową w x h (format BGRA jak pulpit).
func NewProbe(dev, ctx *com.Object, w, h int) (*Probe, error) {
	desc := texDesc{Width: uint32(w), Height: uint32(h), MipLevels: 1, ArraySize: 1, Format: 87 /*B8G8R8A8_UNORM*/, SampleCount: 1, Usage: 3, CPUAccess: 0x20000}
	var tex *com.Object
	if err := com.Check("CreateTexture2D(probe)", com.Call(dev, slotDeviceCreateTexture2, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&tex)))); err != nil {
		return nil, err
	}
	return &Probe{dev: dev, ctx: ctx, stage: tex, W: w, H: h}, nil
}

// Queue kolejkuje kopię prostokąta od (x,y) z tekstury src; trzeba zrobić to przed zwolnieniem klatki pulpitu.
func (p *Probe) Queue(src *com.Object, x, y int) {
	box := [6]uint32{uint32(x), uint32(y), 0, uint32(x + p.W), uint32(y + p.H), 1}
	com.Call(p.ctx, slotCtxCopySubresource, uintptr(unsafe.Pointer(p.stage)), 0, 0, 0, 0, uintptr(unsafe.Pointer(src)), 0, uintptr(unsafe.Pointer(&box)))
}

// Read czeka na zakończenie kopii i zwraca piksele BGRA (kopia) oraz stride.
func (p *Probe) Read() ([]byte, int, error) {
	var ms mappedSubresource
	if err := com.Check("Map(probe)", com.Call(p.ctx, slotCtxMap, uintptr(unsafe.Pointer(p.stage)), 0, 1, 0, uintptr(unsafe.Pointer(&ms)))); err != nil {
		return nil, 0, err
	}
	out := make([]byte, int(ms.RowPitch)*p.H)
	copy(out, unsafe.Slice((*byte)(ms.Data), len(out)))
	com.Call(p.ctx, slotCtxUnmap, uintptr(unsafe.Pointer(p.stage)), 0)
	return out, int(ms.RowPitch), nil
}

// Close zwalnia teksturę.
func (p *Probe) Close() { com.Release(p.stage) }
