//go:build windows

// Package mf wywołuje Media Foundation (koder H.264 jako MFT) z czystego Go przez COM, bez cgo.
package mf

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// Sloty vtable sprawdzone z nagłówków Windows SDK 10.0.26100 (mfobjects.h, mftransform.h, strmif.h).
const (
	slotAttrGetUINT32          = 7
	slotAttrGetGUID            = 10
	slotAttrGetBlobSize        = 14
	slotAttrGetBlob            = 15
	slotAttrGetAllocatedString = 13
	slotAttrSetUINT32          = 21
	slotAttrSetUINT64          = 22
	slotAttrSetGUID            = 24
	slotAttrSetUnknown         = 27

	slotActivateObject = 33

	slotSampleSetTime     = 36
	slotSampleSetDuration = 38
	slotSampleAddBuffer   = 42
	slotSampleConvertCont = 41
	slotSampleGetTotalLen = 45
	slotSampleGetBufCount = 39
	slotSampleGetTime     = 35

	slotBufLock       = 3
	slotBufUnlock     = 4
	slotBufGetCurLen  = 5
	slotBufSetCurLen  = 6
	slotBufGetMaxLen  = 7
	slotEventGenGetEv = 3
	slotEventGetType  = 33
	slotEventGetStat  = 35

	slotMFTGetStreamIDs       = 5
	slotMFTGetInputInfo       = 6
	slotMFTGetOutputInfo      = 7
	slotMFTGetAttributes      = 8
	slotMFTGetInputAvail      = 13
	slotMFTGetOutputAvail     = 14
	slotMFTSetInputType       = 15
	slotMFTSetOutputType      = 16
	slotMFTGetOutputCurrent   = 18
	slotMFTProcessMessage     = 23
	slotMFTProcessInput       = 24
	slotMFTProcessOutput      = 25
	slotCodecSetValue         = 9
	slotDXGIMgrResetDevice    = 7
	slotMFTProcessEventUnused = 22
)

// Komunikaty MFT (mftransform.h).
const (
	msgCommandFlush           = 0x0
	msgCommandDrain           = 0x1
	msgSetD3DManager          = 0x2
	msgNotifyBeginStreaming   = 0x10000000
	msgNotifyEndStreaming     = 0x10000001
	msgNotifyStartOfStream    = 0x10000003
	outputStreamProvidesSmpls = 0x100
)

// Zdarzenia asynchronicznego MFT.
const (
	evTransformNeedInput  = 601
	evTransformHaveOutput = 602
	evTransformDrain      = 603
)

// Znane HRESULT-y.
const (
	mfETransformNeedMoreInput com.HRESULT = 0xC00D6D72
	mfETransformStreamChange  com.HRESULT = 0xC00D6D61
	mfENoMoreTypes            com.HRESULT = 0xC00D36B9
	mfENoEventsAvailable      com.HRESULT = 0x80070 + 0 // niewykorzystywane; zob. noEvents
	mfEShutdown               com.HRESULT = 0xC00D3E85
	mfEUnsupportedD3DType     com.HRESULT = 0xC00D6D75
)

const noEvents com.HRESULT = 0xC00D3E80

// MF_VERSION z mfapi.h (MF_SDK_VERSION 2 << 16 | MF_API_VERSION 0x70).
const mfVersion = 0x00020070

var (
	mfplat = windows.NewLazySystemDLL("mfplat.dll")
	ole32  = windows.NewLazySystemDLL("ole32.dll")
	oleaut = windows.NewLazySystemDLL("oleaut32.dll")

	procMFStartup            = mfplat.NewProc("MFStartup")
	procMFShutdown           = mfplat.NewProc("MFShutdown")
	procMFTEnumEx            = mfplat.NewProc("MFTEnumEx")
	procMFCreateMediaType    = mfplat.NewProc("MFCreateMediaType")
	procMFCreateSample       = mfplat.NewProc("MFCreateSample")
	procMFCreateMemoryBuffer = mfplat.NewProc("MFCreateMemoryBuffer")
	procMFCreateDXGIDevMgr   = mfplat.NewProc("MFCreateDXGIDeviceManager")
	procMFCreateDXGISurfBuf  = mfplat.NewProc("MFCreateDXGISurfaceBuffer")
	procCoCreateInstance     = ole32.NewProc("CoCreateInstance")
	procVariantClear         = oleaut.NewProc("VariantClear")
)

var (
	// Typy i atrybuty (mfapi.h).
	mtMajorType    = com.MustGUID(0x48eba18e, 0xf8c9, 0x4687, 0xbf, 0x11, 0x0a, 0x74, 0xc9, 0xf9, 0x6a, 0x8f)
	mtSubtype      = com.MustGUID(0xf7e34c9a, 0x42e8, 0x4714, 0xb7, 0x4b, 0xcb, 0x29, 0xd7, 0x2c, 0x35, 0xe5)
	mtFrameSize    = com.MustGUID(0x1652c33d, 0xd6b2, 0x4012, 0xb8, 0x34, 0x72, 0x03, 0x08, 0x49, 0xa3, 0x7d)
	mtFrameRate    = com.MustGUID(0xc459a2e8, 0x3d2c, 0x4e44, 0xb1, 0x32, 0xfe, 0xe5, 0x15, 0x6c, 0x7b, 0xb0)
	mtAvgBitrate   = com.MustGUID(0x20332624, 0xfb0d, 0x4d9e, 0xbd, 0x0d, 0xcb, 0xf6, 0x78, 0x6c, 0x10, 0x2e)
	mtInterlace    = com.MustGUID(0xe2724bb8, 0xe676, 0x4806, 0xb4, 0xb2, 0xa8, 0xd6, 0xef, 0xb4, 0x4c, 0xcd)
	mtPixelAspect  = com.MustGUID(0xc6376a1e, 0x8d0a, 0x4027, 0xbe, 0x45, 0x6d, 0x9a, 0x0a, 0xd3, 0x9b, 0xb6)
	mtMPEG2Profile = com.MustGUID(0xad76a80b, 0x2d5c, 0x4e0b, 0xb3, 0x75, 0x64, 0xe5, 0x20, 0x13, 0x70, 0x36)
	mtSeqHeader    = com.MustGUID(0x3c036de7, 0x3ad0, 0x4c9e, 0x92, 0x16, 0xee, 0x6d, 0x6a, 0xc2, 0x1c, 0xb3)

	mediaTypeVideo = com.MustGUID(0x73646976, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71)
	fmtH264        = fourCC('H', '2', '6', '4')
	fmtNV12        = fourCC('N', 'V', '1', '2')
	fmtYUY2        = fourCC('Y', 'U', 'Y', '2')
	fmtI420        = fourCC('I', '4', '2', '0')
	fmtIYUV        = fourCC('I', 'Y', 'U', 'V')
	fmtRGB32       = d3dFmt(22)
	fmtARGB32      = d3dFmt(21)

	catVideoEncoder = com.MustGUID(0xf79eac7d, 0xe545, 0x4387, 0xbd, 0xee, 0xd6, 0x47, 0xd7, 0xbd, 0xe4, 0x2a)

	friendlyName   = com.MustGUID(0x314ffbae, 0x5b41, 0x4c95, 0x9c, 0x19, 0x4e, 0x7d, 0x58, 0x6f, 0xac, 0xe3)
	hwVendorID     = com.MustGUID(0x3aecb0cc, 0x035b, 0x4bcc, 0x81, 0x85, 0x2b, 0x8d, 0x55, 0x1e, 0xf3, 0xaf)
	transformAsync = com.MustGUID(0xf81a699a, 0x649a, 0x497d, 0x8c, 0x73, 0x29, 0xf8, 0xfe, 0xd6, 0xad, 0x7a)
	asyncUnlock    = com.MustGUID(0xe5666d6b, 0x3422, 0x4eb6, 0xa4, 0x21, 0xda, 0x7d, 0xb1, 0xf8, 0xe2, 0x07)
	d3d11Aware     = com.MustGUID(0x206b4fc8, 0xfcf9, 0x4c51, 0xaf, 0xe3, 0x97, 0x64, 0x36, 0x9e, 0x33, 0xa0)

	iidMFTransform = com.MustGUID(0xbf94c121, 0x5b05, 0x4e6f, 0x80, 0x00, 0xba, 0x59, 0x89, 0x61, 0x41, 0x4d)
	iidEventGen    = com.MustGUID(0x2CD0BD52, 0xBCD5, 0x4B89, 0xB6, 0x2C, 0xEA, 0xDC, 0x0C, 0x03, 0x1E, 0x7D)
	iidCodecAPI    = com.MustGUID(0x901db4c7, 0x31ce, 0x41a2, 0x85, 0xdc, 0x8f, 0xa0, 0xbf, 0x41, 0xb8, 0xda)
	clsidMSH264Enc = com.MustGUID(0x6ca50344, 0x051a, 0x4ded, 0x97, 0x79, 0xa4, 0x33, 0x05, 0x16, 0x5e, 0x35)

	// Właściwości ICodecAPI (codecapi.h).
	capLowLatency    = com.MustGUID(0x9c27891a, 0xed7a, 0x40e1, 0x88, 0xe8, 0xb2, 0x27, 0x27, 0xa0, 0x24, 0xee)
	capRateControl   = com.MustGUID(0x1c0608e9, 0x370c, 0x4710, 0x8a, 0x58, 0xcb, 0x61, 0x81, 0xc4, 0x24, 0x23)
	capMeanBitrate   = com.MustGUID(0xf7222374, 0x2144, 0x4815, 0xb5, 0x50, 0xa3, 0x7f, 0x8e, 0x12, 0xee, 0x52)
	capMaxBitrate    = com.MustGUID(0x9651eae4, 0x39b9, 0x4ebf, 0x85, 0xef, 0xd7, 0xf4, 0x44, 0xec, 0x74, 0x65)
	capGOPSize       = com.MustGUID(0x95f31b26, 0x95a4, 0x41aa, 0x93, 0x03, 0x24, 0x6a, 0x7f, 0xc6, 0xee, 0xf1)
	capForceKeyFrame = com.MustGUID(0x398c1b98, 0x8353, 0x475a, 0x9e, 0xf2, 0x8f, 0x26, 0x5d, 0x26, 0x03, 0x45)
	capBPictures     = com.MustGUID(0x8d390aac, 0xdc5c, 0x4200, 0xb5, 0x7f, 0x81, 0x4d, 0x04, 0xba, 0xba, 0xb2)
	capQualitySpeed  = com.MustGUID(0x98332df8, 0x03cd, 0x476b, 0x89, 0xfa, 0x3f, 0x9e, 0x44, 0x2d, 0xec, 0x9f)
	capRealTime      = com.MustGUID(0x143a0ff6, 0xa131, 0x43da, 0xb8, 0x1e, 0x98, 0xfb, 0xb8, 0xec, 0x37, 0x8e)
	capMinQP         = com.MustGUID(0x0ee22c6a, 0xa37c, 0x4568, 0xb5, 0xf1, 0x9d, 0x4c, 0x2b, 0x3a, 0xb8, 0x86)
	capMaxQP         = com.MustGUID(0x3daf6f66, 0xa6a7, 0x45e0, 0xa8, 0xe5, 0xf2, 0x74, 0x3f, 0x46, 0xa3, 0xa2)
)

func fourCC(a, b, c, d byte) com.GUID {
	return d3dFmt(uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24)
}

func d3dFmt(v uint32) com.GUID {
	return com.MustGUID(v, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71)
}

func guidp(g *com.GUID) uintptr { return uintptr(unsafe.Pointer(g)) }

// Startup uruchamia Media Foundation (para z Shutdown).
func Startup() error {
	r, _, _ := procMFStartup.Call(mfVersion, 0)
	return com.Check("MFStartup", com.HRESULT(uint32(r)))
}

// Shutdown kończy Media Foundation.
func Shutdown() { procMFShutdown.Call() }

// ---- atrybuty (IMFAttributes: wspólne dla IMFActivate, IMFMediaType, IMFSample) ----

func setUINT32(o *com.Object, key *com.GUID, v uint32) error {
	return com.Check("SetUINT32", com.Call(o, slotAttrSetUINT32, guidp(key), uintptr(v)))
}

func setUINT64(o *com.Object, key *com.GUID, v uint64) error {
	return com.Check("SetUINT64", com.Call(o, slotAttrSetUINT64, guidp(key), uintptr(v)))
}

func setGUID(o *com.Object, key, v *com.GUID) error {
	return com.Check("SetGUID", com.Call(o, slotAttrSetGUID, guidp(key), guidp(v)))
}

func getUINT32(o *com.Object, key *com.GUID) (uint32, bool) {
	var v uint32
	h := com.Call(o, slotAttrGetUINT32, guidp(key), uintptr(unsafe.Pointer(&v)))
	return v, !h.Failed()
}

func getGUID(o *com.Object, key *com.GUID) (com.GUID, bool) {
	var v com.GUID
	h := com.Call(o, slotAttrGetGUID, guidp(key), uintptr(unsafe.Pointer(&v)))
	return v, !h.Failed()
}

func getString(o *com.Object, key *com.GUID) string {
	var p *uint16
	var n uint32
	h := com.Call(o, slotAttrGetAllocatedString, guidp(key), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n)))
	if h.Failed() || p == nil {
		return ""
	}
	defer com.TaskMemFree(unsafe.Pointer(p))
	return windows.UTF16PtrToString(p)
}

func pack2x32(hi, lo uint32) uint64 { return uint64(hi)<<32 | uint64(lo) }

func unpack2x32(v uint64) (hi, lo uint32) { return uint32(v >> 32), uint32(v) }

// ---- enumeracja koderów ----

// EncoderInfo opisuje znalezionego kodera H.264.
type EncoderInfo struct {
	Name     string
	Hardware bool
	VendorID string
	Async    bool
	activate *com.Object
}

// MatchesVendor mówi, czy koder należy do karty o danym identyfikatorze PCI producenta (MFT podaje „VEN_8086”).
func (e EncoderInfo) MatchesVendor(vendor uint32) bool {
	return vendor != 0 && strings.Contains(strings.ToUpper(e.VendorID), fmt.Sprintf("VEN_%04X", vendor))
}

type registerTypeInfo struct {
	Major com.GUID
	Sub   com.GUID
}

// EnumEncoders zwraca kodery H.264 (sprzętowe, potem programowe) w kolejności preferencji systemu.
func EnumEncoders() ([]EncoderInfo, error) {
	var out []EncoderInfo
	for _, hw := range []bool{true, false} {
		flags := uint32(0x40) // SORTANDFILTER
		if hw {
			flags |= 0x04 // HARDWARE
		} else {
			flags |= 0x01 | 0x02 // SYNCMFT | ASYNCMFT
		}
		outType := registerTypeInfo{Major: mediaTypeVideo, Sub: fmtH264}
		var arr **com.Object
		var count uint32
		r, _, _ := procMFTEnumEx.Call(guidp(&catVideoEncoder), uintptr(flags), 0, uintptr(unsafe.Pointer(&outType)),
			uintptr(unsafe.Pointer(&arr)), uintptr(unsafe.Pointer(&count)))
		if err := com.Check("MFTEnumEx", com.HRESULT(uint32(r))); err != nil {
			return nil, err
		}
		if count > 0 && arr != nil {
			items := unsafe.Slice(arr, count)
			for _, a := range items {
				info := EncoderInfo{Hardware: hw, activate: a}
				info.Name = getString(a, &friendlyName)
				info.VendorID = getString(a, &hwVendorID)
				if v, ok := getUINT32(a, &transformAsync); ok && v != 0 {
					info.Async = true
				}
				out = append(out, info)
			}
			com.TaskMemFree(unsafe.Pointer(arr))
		}
	}
	return out, nil
}

// TryActivate sprawdza, czy koder daje się aktywować (ActivateObject) i od razu go zwalnia; zwraca błąd z HRESULT.
func TryActivate(e EncoderInfo) error {
	var mft *com.Object
	h := com.Call(e.activate, slotActivateObject, uintptr(unsafe.Pointer(&iidMFTransform)), uintptr(unsafe.Pointer(&mft)))
	if h.Failed() {
		return fmt.Errorf("ActivateObject: %w", h)
	}
	com.Release(mft)
	com.Call(e.activate, 34) // ShutdownObject
	return nil
}

// UTF-16 pomocniczo dla wywołań, które potrzebują napisów szerokich.
func utf16z(s string) *uint16 {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	return &u[0]
}

var _ = fmt.Sprintf
var _ = utf16z
