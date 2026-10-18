//go:build windows

package mf

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// Debug włącza logowanie zdarzeń MFT na stdout.
var Debug bool

// relStat zlicza, ile razy po Release pozostała dana liczba referencji (diagnozowanie wycieków obiektów COM).
type relStat struct{ zero, one, more atomic.Int64 }

var relEv, relSmp, relBuf relStat

// seenSmp zbiera różne adresy próbek wyjściowych: mało = pula MFT, tyle co klatek = każda próbka nowa (podejrzenie wycieku).
var seenSmp = struct {
	sync.Mutex
	m map[uintptr]struct{}
}{m: map[uintptr]struct{}{}}

func recordRelease(s *relStat, remaining uint32) {
	switch {
	case remaining == 0:
		s.zero.Add(1)
	case remaining == 1:
		s.one.Add(1)
	default:
		s.more.Add(1)
	}
}

// ReleaseReport opisuje, co zostało po zwolnieniu zdarzeń, próbek i buforów wyjściowych (0 = obiekt zniszczony).
func ReleaseReport() string {
	f := func(n string, s *relStat) string {
		return fmt.Sprintf("%s: zniszczone=%d, zostaje1=%d, zostaje>1=%d", n, s.zero.Load(), s.one.Load(), s.more.Load())
	}
	seenSmp.Lock()
	n := len(seenSmp.m)
	seenSmp.Unlock()
	return f("zdarzenia", &relEv) + "; " + f("próbki wyjściowe", &relSmp) + "; " + f("bufory wyjściowe", &relBuf) + fmt.Sprintf("; różnych adresów próbek wyjściowych: %d", n)
}

// skip pozwala wyłączać fragmenty konfiguracji zmienną MF_SKIP (lista po przecinku) przy diagnozowaniu koderów.
func skip(what string) bool {
	for _, s := range strings.Split(os.Getenv("MF_SKIP"), ",") {
		if s == what {
			return true
		}
	}
	return false
}

// Config opisuje parametry kodera H.264 do strumienia pulpitu (małe opóźnienie, bez klatek B).
type Config struct {
	Width, Height int
	FPS           int
	BitrateKbps   int
	GOP           int    // długość GOP w klatkach; 0 = 10 s
	Prefer        string // "auto", "nvidia", "intel", "software"
	Profile       uint32 // 66 = Base (domyślnie), 77 = Main, 100 = High
	LowLatencyRC  string // "cbr" (domyślnie), "lowdelayvbr", "quality"
	// D3DDevice: urządzenie D3D11 współdzielone z przechwytywaniem (musi mieć VIDEO_SUPPORT i być chronione
	// wielowątkowo). Wtedy koder może przyjmować tekstury NV12 z GPU (EncodeSample) bez kopiowania przez procesor.
	D3DDevice *com.Object
	// VendorID to identyfikator PCI producenta karty wyświetlającej monitor (DXGI); jej kodery sprzętowe idą pierwsze.
	VendorID uint32
	// RequireVendor ogranicza wybór do koderów sprzętowych tej karty (koder na innym urządzeniu D3D11 nie przyjmie tekstur).
	RequireVendor bool
}

// Encoder to koder H.264 oparty na MFT. Nie jest bezpieczny wątkowo: używaj z jednego wątku.
type Encoder struct {
	Info  EncoderInfo
	Notes []string // ostrzeżenia z konfiguracji (nieobsługiwane właściwości)

	cfg      Config
	mft      *com.Object
	codec    *com.Object
	events   *com.Object
	evCh     chan mfEvent
	needIn   int
	nv12Size int
	provides bool
	outBufSz uint32
	outSmp   *com.Object // własna próbka wyjściowa, gdy MFT jej nie dostarcza
	inRing   []*inSample
	ringPos  int
	closed   bool
	forceKey bool
	seqHdr   []byte
	inAlign  uint32

	d3dDev, d3dCtx, d3dMgr *com.Object
}

type inSample struct {
	smp *com.Object
	buf *com.Object
}

type mfEvent struct {
	typ uint32
	hr  com.HRESULT
}

type variant struct {
	vt  uint16
	_   [3]uint16
	val uint64
	_   uint64
}

type outputDataBuffer struct {
	StreamID uint32
	Sample   *com.Object
	Status   uint32
	Events   *com.Object
}

type streamInfo struct {
	Flags, Size, Align uint32
}

// Result to jedna zakodowana klatka.
type Result struct {
	Data      []byte // Annex B (kody startowe), z SPS/PPS przy klatce kluczowej
	Key       bool
	EncodeDur time.Duration
}

func pickEncoder(infos []EncoderInfo, prefer string) (EncoderInfo, error) {
	prefer = strings.ToLower(prefer)
	if strings.HasPrefix(prefer, "#") {
		var idx int
		if _, err := fmt.Sscanf(prefer, "#%d", &idx); err == nil && idx >= 0 && idx < len(infos) {
			return infos[idx], nil
		}
	}
	for _, i := range infos {
		switch prefer {
		case "", "auto":
			return i, nil
		case "nvidia":
			if i.Hardware && strings.Contains(strings.ToLower(i.Name), "nvidia") {
				return i, nil
			}
		case "intel":
			if i.Hardware && strings.Contains(strings.ToLower(i.Name), "intel") {
				return i, nil
			}
		case "software", "sw":
			if !i.Hardware {
				return i, nil
			}
		}
	}
	return EncoderInfo{}, fmt.Errorf("brak kodera H.264 dla %q", prefer)
}

// NewEncoder tworzy i konfiguruje koder. Wątek wywołujący musi mieć zainicjowany COM (com.InitMTA) i MFStartup.
func NewEncoder(cfg Config) (*Encoder, error) {
	if cfg.Width%2 != 0 || cfg.Height%2 != 0 {
		return nil, errors.New("rozmiar musi być parzysty")
	}
	if cfg.FPS <= 0 {
		cfg.FPS = 60
	}
	if cfg.BitrateKbps <= 0 {
		cfg.BitrateKbps = 6000
	}
	if cfg.GOP <= 0 {
		cfg.GOP = cfg.FPS * 10
	}
	if cfg.Profile == 0 {
		cfg.Profile = 66
	}
	infos, err := EnumEncoders()
	if err != nil {
		return nil, err
	}
	candidates, err := orderEncoders(infos, cfg)
	if err != nil {
		return nil, err
	}
	// Kodery próbujemy po kolei: na laptopie z dwiema kartami pierwszy na liście systemu (NVIDIA) potrafi odmówić
	// aktywacji (0x8000FFFF), a koder karty, która wyświetla monitor, działa.
	var errs []error
	for _, info := range candidates {
		e := &Encoder{Info: info, cfg: cfg, nv12Size: cfg.Width * cfg.Height * 3 / 2}
		var mft *com.Object
		if err := com.Check("ActivateObject", com.Call(info.activate, slotActivateObject, uintptr(unsafe.Pointer(&iidMFTransform)), uintptr(unsafe.Pointer(&mft)))); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", info.Name, err))
			continue
		}
		e.mft = mft
		if err := e.configure(); err != nil {
			e.Close()
			errs = append(errs, fmt.Errorf("%s: %w", info.Name, err))
			continue
		}
		for _, err := range errs {
			e.note("pominięty koder: %v", err)
		}
		return e, nil
	}
	return nil, fmt.Errorf("żaden koder H.264 nie działa: %w", errors.Join(errs...))
}

// orderEncoders układa kodery w kolejności prób: wskazany jawnie (#N albo producent), inaczej sprzętowe karty
// wyświetlającej monitor (VendorID), potem pozostałe sprzętowe, na końcu programowy. Przy RequireVendor (ścieżka GPU
// na urządzeniu D3D11 tej karty) zostają tylko sprzętowe tej karty.
func orderEncoders(infos []EncoderInfo, cfg Config) ([]EncoderInfo, error) {
	prefer := strings.ToLower(cfg.Prefer)
	if prefer != "" && prefer != "auto" {
		info, err := pickEncoder(infos, prefer)
		if err != nil {
			return nil, err
		}
		return []EncoderInfo{info}, nil
	}
	var same, other, soft []EncoderInfo
	for _, i := range infos {
		switch {
		case i.Hardware && cfg.VendorID != 0 && i.MatchesVendor(cfg.VendorID):
			same = append(same, i)
		case i.Hardware:
			other = append(other, i)
		default:
			soft = append(soft, i)
		}
	}
	out := append(same, other...)
	if cfg.RequireVendor {
		out = same
	} else {
		out = append(out, soft...)
	}
	if len(out) == 0 {
		return nil, errors.New("brak kodera H.264 w systemie")
	}
	return out, nil
}

func (e *Encoder) note(format string, a ...any) { e.Notes = append(e.Notes, fmt.Sprintf(format, a...)) }

func (e *Encoder) setCodecU32(key *com.GUID, v uint32) {
	if e.codec == nil {
		return
	}
	va := variant{vt: 19, val: uint64(v)} // VT_UI4
	if h := com.Call(e.codec, slotCodecSetValue, guidp(key), uintptr(unsafe.Pointer(&va))); h.Failed() {
		e.note("ICodecAPI.SetValue(%v)=%v", *key, h)
	}
}

func (e *Encoder) setCodecBool(key *com.GUID, v bool) {
	if e.codec == nil {
		return
	}
	va := variant{vt: 11} // VT_BOOL
	if v {
		va.val = 0xFFFF
	}
	if h := com.Call(e.codec, slotCodecSetValue, guidp(key), uintptr(unsafe.Pointer(&va))); h.Failed() {
		e.note("ICodecAPI.SetValue(%v)=%v", *key, h)
	}
}

func (e *Encoder) configure() error {
	cfg := e.cfg
	// Hardware MFT są asynchroniczne i wymagają odblokowania.
	var attrs *com.Object
	if h := com.Call(e.mft, slotMFTGetAttributes, uintptr(unsafe.Pointer(&attrs))); !h.Failed() && attrs != nil {
		if v, ok := getUINT32(attrs, &transformAsync); ok && v != 0 {
			if err := setUINT32(attrs, &asyncUnlock, 1); err != nil {
				return fmt.Errorf("odblokowanie MFT async: %w", err)
			}
			e.Info.Async = true
		}
		// Niskie opóźnienie także jako atrybut MFT (część koderów czyta tylko to).
		if !skip("attrlowlat") {
			setUINT32(attrs, &capLowLatency, 1)
		}
		com.Release(attrs)
	}
	if e.Info.Async {
		ev, err := com.QueryInterface(e.mft, &iidEventGen)
		if err != nil {
			return fmt.Errorf("IMFMediaEventGenerator: %w", err)
		}
		e.events = ev
		e.evCh = make(chan mfEvent, 16)
		go e.pump(ev)
	}
	if c, err := com.QueryInterface(e.mft, &iidCodecAPI); err == nil {
		e.codec = c
	} else {
		e.note("brak ICodecAPI: %v", err)
	}

	if e.Info.Hardware && !skip("d3d") {
		if err := e.setupD3D(); err != nil {
			e.note("D3D manager: %v", err)
		}
	}
	if skip("codec") {
		e.codec = nil
	}
	e.setCodecBool(&capLowLatency, true)
	if !skip("realtime") {
		e.setCodecBool(&capRealTime, true)
	}
	rc := uint32(0) // CBR
	switch strings.ToLower(cfg.LowLatencyRC) {
	case "lowdelayvbr":
		rc = 4
	case "quality":
		rc = 3
	}
	if !skip("rc") {
		e.setCodecU32(&capRateControl, rc)
	}
	if !skip("bitrate") {
		e.setCodecU32(&capMeanBitrate, uint32(cfg.BitrateKbps)*1000)
	}
	if !skip("gop") {
		e.setCodecU32(&capGOPSize, uint32(cfg.GOP))
	}
	if !skip("bpic") {
		e.setCodecU32(&capBPictures, 0)
	}

	// Typ wyjściowy (H.264) musi być ustawiony przed wejściowym.
	var ot *com.Object
	if err := com.Check("MFCreateMediaType", createMediaType(&ot)); err != nil {
		return err
	}
	defer com.Release(ot)
	setGUID(ot, &mtMajorType, &mediaTypeVideo)
	setGUID(ot, &mtSubtype, &fmtH264)
	setUINT32(ot, &mtAvgBitrate, uint32(cfg.BitrateKbps)*1000)
	setUINT64(ot, &mtFrameSize, pack2x32(uint32(cfg.Width), uint32(cfg.Height)))
	setUINT64(ot, &mtFrameRate, pack2x32(uint32(cfg.FPS), 1))
	setUINT64(ot, &mtPixelAspect, pack2x32(1, 1))
	setUINT32(ot, &mtInterlace, 2) // MFVideoInterlace_Progressive
	if !skip("profile") {
		setUINT32(ot, &mtMPEG2Profile, cfg.Profile)
	}
	if err := com.Check("SetOutputType", com.Call(e.mft, slotMFTSetOutputType, 0, uintptr(unsafe.Pointer(ot)), 0)); err != nil {
		return err
	}

	var it *com.Object
	if err := com.Check("MFCreateMediaType", createMediaType(&it)); err != nil {
		return err
	}
	defer com.Release(it)
	setGUID(it, &mtMajorType, &mediaTypeVideo)
	setGUID(it, &mtSubtype, &fmtNV12)
	setUINT64(it, &mtFrameSize, pack2x32(uint32(cfg.Width), uint32(cfg.Height)))
	setUINT64(it, &mtFrameRate, pack2x32(uint32(cfg.FPS), 1))
	setUINT64(it, &mtPixelAspect, pack2x32(1, 1))
	setUINT32(it, &mtInterlace, 2)
	if err := com.Check("SetInputType(NV12)", com.Call(e.mft, slotMFTSetInputType, 0, uintptr(unsafe.Pointer(it)), 0)); err != nil {
		return err
	}

	var osi streamInfo
	if err := com.Check("GetOutputStreamInfo", com.Call(e.mft, slotMFTGetOutputInfo, 0, uintptr(unsafe.Pointer(&osi)))); err != nil {
		return err
	}
	e.provides = osi.Flags&outputStreamProvidesSmpls != 0
	e.note("output stream info: flags=0x%X size=%d align=%d", osi.Flags, osi.Size, osi.Align)
	var isi struct {
		MaxLatency                    int64
		Flags, Size, Lookahead, Align uint32
	}
	if h := com.Call(e.mft, slotMFTGetInputInfo, 0, uintptr(unsafe.Pointer(&isi))); !h.Failed() {
		e.note("input stream info: flags=0x%X size=%d lookahead=%d align=%d maxlatency=%d", isi.Flags, isi.Size, isi.Lookahead, isi.Align, isi.MaxLatency)
		e.inAlign = isi.Align
	}
	e.outBufSz = osi.Size
	if !e.provides {
		smp, err := newSample(int(osi.Size) + int(osi.Size)/2 + 1<<16)
		if err != nil {
			return err
		}
		e.outSmp = smp.smp
	}
	for i := 0; i < 4; i++ {
		s, err := newSample(e.nv12Size)
		if err != nil {
			return err
		}
		e.inRing = append(e.inRing, s)
	}

	com.Call(e.mft, slotMFTProcessMessage, msgNotifyBeginStreaming, 0)
	com.Call(e.mft, slotMFTProcessMessage, msgNotifyStartOfStream, 0)
	return nil
}

var iidD3D10Multithread = com.MustGUID(0x9B7E4E00, 0x342C, 0x4106, 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0)

// setupD3D daje sprzętowemu koderowi urządzenie D3D11 z karty jego producenta (menedżer urządzeń DXGI).
func (e *Encoder) setupD3D() error {
	dev, ctx := e.cfg.D3DDevice, (*com.Object)(nil)
	idx := -1
	if dev == nil {
		var vendor uint32
		if _, err := fmt.Sscanf(strings.ToUpper(e.Info.VendorID), "VEN_%X", &vendor); err != nil {
			return fmt.Errorf("nieznany producent %q", e.Info.VendorID)
		}
		adapters, err := capture.ListAdapters()
		if err != nil {
			return err
		}
		for _, a := range adapters {
			if a.VendorID == vendor && a.Flags&2 == 0 { // 2 = DXGI_ADAPTER_FLAG_SOFTWARE
				idx = a.Index
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("brak karty producenta %04X", vendor)
		}
		dev, ctx, err = capture.CreateDevice(idx, 0x800|0x20) // VIDEO_SUPPORT | BGRA_SUPPORT
		if err != nil {
			return err
		}
		if mt, err := com.QueryInterface(dev, &iidD3D10Multithread); err == nil {
			com.Call(mt, 5, 1) // SetMultithreadProtected(TRUE)
			com.Release(mt)
		}
	}
	var token uint32
	var mgr *com.Object
	r, _, _ := procMFCreateDXGIDevMgr.Call(uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&mgr)))
	if err := com.Check("MFCreateDXGIDeviceManager", com.HRESULT(uint32(r))); err != nil {
		return err
	}
	if err := com.Check("ResetDevice", com.Call(mgr, slotDXGIMgrResetDevice, uintptr(unsafe.Pointer(dev)), uintptr(token))); err != nil {
		return err
	}
	if err := com.Check("SET_D3D_MANAGER", com.Call(e.mft, slotMFTProcessMessage, msgSetD3DManager, uintptr(unsafe.Pointer(mgr)))); err != nil {
		return err
	}
	if e.cfg.D3DDevice == nil { // własne urządzenie zwalniamy sami; współdzielone należy do wołającego
		e.d3dDev, e.d3dCtx = dev, ctx
	}
	e.d3dMgr = mgr
	e.note("menedżer D3D11 ustawiony (karta %d, współdzielone=%v)", idx, e.cfg.D3DDevice != nil)
	return nil
}

// TexSample to próbka MF owijająca teksturę NV12 z GPU (bufor powierzchni DXGI), do kodowania bez kopii przez procesor.
type TexSample struct{ smp, buf *com.Object }

// Release zwalnia próbkę (nie teksturę).
func (t *TexSample) Release() {
	com.Release(t.buf)
	com.Release(t.smp)
}

// NewTextureSample owija teksturę NV12 (ID3D11Texture2D z urządzenia Config.D3DDevice) w próbkę wejściową.
func (e *Encoder) NewTextureSample(tex *com.Object) (*TexSample, error) {
	if e.d3dMgr == nil {
		return nil, errors.New("koder nie ma menedżera D3D11 (wymagany sprzętowy MFT i Config.D3DDevice)")
	}
	var smp, buf *com.Object
	r, _, _ := procMFCreateSample.Call(uintptr(unsafe.Pointer(&smp)))
	if err := com.Check("MFCreateSample", com.HRESULT(uint32(r))); err != nil {
		return nil, err
	}
	r, _, _ = procMFCreateDXGISurfBuf.Call(uintptr(unsafe.Pointer(&iidD3D11Texture2D)), uintptr(unsafe.Pointer(tex)), 0, 0, uintptr(unsafe.Pointer(&buf)))
	if err := com.Check("MFCreateDXGISurfaceBuffer", com.HRESULT(uint32(r))); err != nil {
		com.Release(smp)
		return nil, err
	}
	com.Call(buf, slotBufSetCurLen, uintptr(e.nv12Size))
	if err := com.Check("AddBuffer", com.Call(smp, slotSampleAddBuffer, uintptr(unsafe.Pointer(buf)))); err != nil {
		com.Release(buf)
		com.Release(smp)
		return nil, err
	}
	return &TexSample{smp: smp, buf: buf}, nil
}

var iidD3D11Texture2D = com.MustGUID(0x6f15aaf2, 0xd208, 0x4e89, 0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c)

// EncodeSample koduje teksturę NV12 z GPU opakowaną przez NewTextureSample.
func (e *Encoder) EncodeSample(s *TexSample, pts, dur time.Duration) (*Result, error) {
	t0 := time.Now()
	if e.forceKey {
		e.forceKey = false
		e.setCodecU32(&capForceKeyFrame, 1)
	}
	com.Call(s.smp, slotSampleSetTime, uintptr(pts/100))
	com.Call(s.smp, slotSampleSetDuration, uintptr(dur/100))
	var res *Result
	var err error
	if e.Info.Async {
		res, err = e.encodeAsync(s.smp)
	} else {
		res, err = e.encodeSync(s.smp)
	}
	if res != nil {
		res.EncodeDur = time.Since(t0)
	}
	return res, err
}

func createMediaType(out **com.Object) com.HRESULT {
	r, _, _ := procMFCreateMediaType.Call(uintptr(unsafe.Pointer(out)))
	return com.HRESULT(uint32(r))
}

func newSample(size int) (*inSample, error) {
	var smp, buf *com.Object
	r, _, _ := procMFCreateSample.Call(uintptr(unsafe.Pointer(&smp)))
	if err := com.Check("MFCreateSample", com.HRESULT(uint32(r))); err != nil {
		return nil, err
	}
	r, _, _ = procMFCreateMemoryBuffer.Call(uintptr(size), uintptr(unsafe.Pointer(&buf)))
	if err := com.Check("MFCreateMemoryBuffer", com.HRESULT(uint32(r))); err != nil {
		com.Release(smp)
		return nil, err
	}
	if err := com.Check("AddBuffer", com.Call(smp, slotSampleAddBuffer, uintptr(unsafe.Pointer(buf)))); err != nil {
		return nil, err
	}
	return &inSample{smp: smp, buf: buf}, nil
}

// pump odbiera zdarzenia asynchronicznego MFT i przekazuje je kanałem.
func (e *Encoder) pump(gen *com.Object) {
	for {
		var ev *com.Object
		h := com.Call(gen, slotEventGenGetEv, 0, uintptr(unsafe.Pointer(&ev)))
		if h.Failed() {
			close(e.evCh)
			return
		}
		var t uint32
		var st com.HRESULT
		com.Call(ev, slotEventGetType, uintptr(unsafe.Pointer(&t)))
		com.Call(ev, slotEventGetStat, uintptr(unsafe.Pointer(&st)))
		recordRelease(&relEv, com.ReleaseCount(ev))
		if Debug {
			fmt.Printf("  [mf] zdarzenie %d status=%v\n", t, st)
		}
		e.evCh <- mfEvent{typ: t, hr: st}
	}
}

// ForceKeyFrame wymusza klatkę IDR na następnej kodowanej klatce.
func (e *Encoder) ForceKeyFrame() { e.forceKey = true }

// Encode koduje jedną klatkę NV12 (rozmiar z konfiguracji). pts to czas od początku strumienia.
// Zwraca nil, jeśli koder nie wydał jeszcze danych (nie powinno się zdarzać w trybie niskiego opóźnienia).
func (e *Encoder) Encode(nv12 []byte, pts, dur time.Duration) (*Result, error) {
	if len(nv12) != e.nv12Size {
		return nil, fmt.Errorf("zły rozmiar NV12: %d, oczekiwano %d", len(nv12), e.nv12Size)
	}
	t0 := time.Now()
	if e.forceKey {
		e.forceKey = false
		e.setCodecU32(&capForceKeyFrame, 1)
	}
	s := e.inRing[e.ringPos]
	e.ringPos = (e.ringPos + 1) % len(e.inRing)
	var p *byte
	var maxLen, curLen uint32
	if err := com.Check("Lock", com.Call(s.buf, slotBufLock, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&maxLen)), uintptr(unsafe.Pointer(&curLen)))); err != nil {
		return nil, err
	}
	copy(unsafe.Slice(p, e.nv12Size), nv12)
	com.Call(s.buf, slotBufUnlock)
	com.Call(s.buf, slotBufSetCurLen, uintptr(e.nv12Size))
	com.Call(s.smp, slotSampleSetTime, uintptr(pts/100))
	com.Call(s.smp, slotSampleSetDuration, uintptr(dur/100))

	var res *Result
	var err error
	if e.Info.Async {
		res, err = e.encodeAsync(s.smp)
	} else {
		res, err = e.encodeSync(s.smp)
	}
	if res != nil {
		res.EncodeDur = time.Since(t0)
	}
	return res, err
}

func (e *Encoder) encodeSync(smp *com.Object) (*Result, error) {
	if err := com.Check("ProcessInput", com.Call(e.mft, slotMFTProcessInput, 0, uintptr(unsafe.Pointer(smp)), 0)); err != nil {
		return nil, err
	}
	for i := 0; i < 3; i++ {
		res, change, err := e.processOutput()
		if err != nil || !change {
			return res, err
		}
	}
	return nil, errors.New("ProcessOutput: za wiele zmian formatu")
}

func (e *Encoder) encodeAsync(smp *com.Object) (*Result, error) {
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	// Czekaj na prośbę o dane wejściowe.
	for e.needIn == 0 {
		select {
		case ev, ok := <-e.evCh:
			if !ok {
				return nil, errors.New("MFT zakończył się")
			}
			if ev.typ == evTransformNeedInput {
				e.needIn++
			}
		case <-timeout.C:
			return nil, errors.New("MFT nie poprosił o dane wejściowe w 3 s")
		}
	}
	e.needIn--
	if err := com.Check("ProcessInput", com.Call(e.mft, slotMFTProcessInput, 0, uintptr(unsafe.Pointer(smp)), 0)); err != nil {
		return nil, err
	}
	for {
		select {
		case ev, ok := <-e.evCh:
			if !ok {
				return nil, errors.New("MFT zakończył się")
			}
			switch ev.typ {
			case evTransformNeedInput:
				e.needIn++
			case evTransformHaveOutput:
				res, change, err := e.processOutput()
				if err != nil || !change {
					return res, err
				}
			}
		case <-timeout.C:
			return nil, errors.New("MFT nie wydał danych w 3 s")
		}
	}
}

// processOutput pobiera jedną zakodowaną klatkę. streamChange=true oznacza, że MFT zgłosił zmianę typu wyjścia
// (typowe przy pierwszej klatce): typ został przyjęty, a prawdziwa klatka przyjdzie przy następnym wywołaniu
// (w trybie async po kolejnym zdarzeniu METransformHaveOutput, bo wcześniejsze wołanie daje E_UNEXPECTED).
func (e *Encoder) processOutput() (res *Result, streamChange bool, err error) {
	var odb outputDataBuffer
	if !e.provides {
		odb.Sample = e.outSmp
		var ob *com.Object
		com.Call(e.outSmp, slotSampleConvertCont, uintptr(unsafe.Pointer(&ob)))
		if ob != nil {
			com.Call(ob, slotBufSetCurLen, 0)
			com.Release(ob)
		}
	}
	var status uint32
	h := com.Call(e.mft, slotMFTProcessOutput, 0, 1, uintptr(unsafe.Pointer(&odb)), uintptr(unsafe.Pointer(&status)))
	switch {
	case h == mfETransformNeedMoreInput:
		return nil, false, nil
	case h == mfETransformStreamChange:
		var t *com.Object
		if hh := com.Call(e.mft, slotMFTGetOutputAvail, 0, 0, uintptr(unsafe.Pointer(&t))); !hh.Failed() {
			com.Call(e.mft, slotMFTSetOutputType, 0, uintptr(unsafe.Pointer(t)), 0)
			com.Release(t)
		}
		return nil, true, nil
	case h.Failed():
		return nil, false, fmt.Errorf("ProcessOutput: %w (provides=%v, status=0x%X, odb.status=0x%X)", h, e.provides, status, odb.Status)
	}
	smp := odb.Sample
	if smp == nil {
		return nil, false, nil
	}
	data, err := readSample(smp)
	if e.provides {
		seenSmp.Lock()
		seenSmp.m[uintptr(unsafe.Pointer(smp))] = struct{}{}
		seenSmp.Unlock()
		recordRelease(&relSmp, com.ReleaseCount(smp))
	}
	if odb.Events != nil {
		com.Release(odb.Events)
	}
	if err != nil {
		return nil, false, err
	}
	return e.finish(data), false, nil
}

func readSample(smp *com.Object) ([]byte, error) {
	var buf *com.Object
	if err := com.Check("ConvertToContiguousBuffer", com.Call(smp, slotSampleConvertCont, uintptr(unsafe.Pointer(&buf)))); err != nil {
		return nil, err
	}
	defer func() { recordRelease(&relBuf, com.ReleaseCount(buf)) }()
	var p *byte
	var maxLen, curLen uint32
	if err := com.Check("Lock(out)", com.Call(buf, slotBufLock, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&maxLen)), uintptr(unsafe.Pointer(&curLen)))); err != nil {
		return nil, err
	}
	out := make([]byte, curLen)
	copy(out, unsafe.Slice(p, curLen))
	com.Call(buf, slotBufUnlock)
	return out, nil
}

// finish wykrywa klatkę kluczową i dba, by SPS/PPS były w strumieniu przy każdej klatce IDR.
func (e *Encoder) finish(data []byte) *Result {
	nals := SplitAnnexB(data)
	var sps, pps []byte
	key := false
	hasParams := false
	for _, n := range nals {
		switch n.Type {
		case 5:
			key = true
		case 7:
			sps = n.Data
			hasParams = true
		case 8:
			pps = n.Data
		}
	}
	if sps != nil && pps != nil {
		hdr := append([]byte{0, 0, 0, 1}, sps...)
		hdr = append(hdr, 0, 0, 0, 1)
		e.seqHdr = append(hdr, pps...)
	}
	if key && !hasParams && e.seqHdr != nil {
		data = append(append([]byte{}, e.seqHdr...), data...)
	}
	return &Result{Data: data, Key: key}
}

// Close zwalnia koder.
func (e *Encoder) Close() {
	if e.closed {
		return
	}
	e.closed = true
	if e.mft != nil {
		com.Call(e.mft, slotMFTProcessMessage, msgNotifyEndStreaming, 0)
	}
	if e.Info.activate != nil {
		com.Call(e.Info.activate, 34) // ShutdownObject: odblokowuje pump
	}
	for _, s := range e.inRing {
		com.Release(s.buf)
		com.Release(s.smp)
	}
	com.Release(e.outSmp)
	com.Release(e.codec)
	com.Release(e.events)
	com.Release(e.mft)
	com.Release(e.d3dMgr)
	com.Release(e.d3dCtx)
	com.Release(e.d3dDev)
}
