//go:build windows

package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/mf"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
)

// Sink przyjmuje zakodowane klatki i zmiany kursora. Wołane z wątku silnika.
type Sink interface {
	// WriteFrame dostaje klatkę H.264 (Annex B, z SPS/PPS przy klatce kluczowej), jej znacznik RTP (90 kHz)
	// i czas ścienny przechwycenia (ms od epoki Unix, do pomiaru opóźnienia po stronie widza).
	WriteFrame(data []byte, key bool, rtpTS uint32, capturedMs float64) error
	// Pointer dostaje położenie i kształt kursora względem kodowanego monitora.
	Pointer(p capture.Pointer)
}

// Engine prowadzi jedną pętlę przechwytywania naraz. Reconfigure i RequestKeyFrame można wołać z innych wątków.
type Engine struct {
	log    *slog.Logger
	gen    atomic.Int64 // rośnie przy Reconfigure
	keyReq atomic.Bool

	mu     sync.Mutex
	cfg    Config
	stats  Stats
	path   PathInfo
	reason string
	onPath func(PathInfo)

	// td to pulpit wejściowy, do którego dołączony jest wątek silnika (używane tylko na wątku silnika).
	td capture.ThreadDesktop
}

// New tworzy silnik z konfiguracją startową.
func New(cfg Config, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{cfg: cfg.normalized(), log: log}
}

// Reconfigure zmienia monitor, klatki lub ścieżkę; pętla uruchomi się od nowa na tym samym połączeniu.
func (e *Engine) Reconfigure(change func(*Config)) {
	e.mu.Lock()
	c := e.cfg
	change(&c)
	e.cfg = c.normalized()
	e.mu.Unlock()
	e.gen.Add(1)
}

// Config zwraca bieżącą konfigurację.
func (e *Engine) Config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// RequestKeyFrame prosi o klatkę kluczową przy następnej okazji (PLI/FIR od widza).
func (e *Engine) RequestKeyFrame() { e.keyReq.Store(true) }

// Stats zwraca liczniki.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

func (e *Engine) setInfo(enc, path string, w, h, fps int) {
	e.mu.Lock()
	e.stats.Encoder, e.stats.Path, e.stats.Width, e.stats.Height, e.stats.FPS = enc, path, w, h, fps
	info := PathInfo{Path: path, Degraded: path == PathGDI}
	if info.Degraded {
		info.Reason = e.reason
	}
	changed := info != e.path
	e.path = info
	cb := e.onPath
	e.mu.Unlock()
	if changed && cb != nil {
		cb(info)
	}
}

// Path zwraca ścieżkę, na której silnik pracuje teraz (pusta Path, dopóki żadna nie wystartowała).
func (e *Engine) Path() PathInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.path
}

// SetOnPath ustawia wywołanie przy każdej zmianie ścieżki (start, zejście na GDI, powrót na szybką); wołane z wątku silnika.
func (e *Engine) SetOnPath(fn func(PathInfo)) {
	e.mu.Lock()
	e.onPath = fn
	e.mu.Unlock()
}

func (e *Engine) setReason(s string) {
	if len(s) > 200 {
		s = s[:200]
	}
	e.mu.Lock()
	e.reason = s
	e.mu.Unlock()
}

// attachDesktop dołącza wątek silnika do pulpitu wejściowego; zwraca jego nazwę do logów.
func (e *Engine) attachDesktop() (string, error) { return e.td.Attach() }

// transientOpenError mówi, czy błąd otwarcia źródła warto ponowić: odmowa dostępu i „chwilowo niedostępne” znikają same
// po przełączeniu pulpitu; „nieobsługiwane” i brak urządzenia nie znikną.
func transientOpenError(err error) bool {
	var h com.HRESULT
	if !errors.As(err, &h) {
		return true // nieznany błąd: ponów, kilka prób nie szkodzi
	}
	switch uint32(h) {
	case 0x80070005, // E_ACCESSDENIED
		0x887A0022, // DXGI_ERROR_NOT_CURRENTLY_AVAILABLE
		0x887A0026, // DXGI_ERROR_ACCESS_LOST
		0x887A0028, // DXGI_ERROR_SESSION_DISCONNECTED
		0x887A0027: // DXGI_ERROR_WAIT_TIMEOUT
		return true
	}
	return false
}

// probeDXGI sprawdza (na osobnym, zablokowanym wątku, dołączonym do pulpitu wejściowego), czy duplikację monitora da się
// teraz otworzyć. Nie koduje i nie zostawia niczego otwartego.
func (e *Engine) probeDXGI() error {
	cfg := e.Config()
	displays, err := capture.ListDisplays()
	if err != nil {
		return err
	}
	if cfg.Monitor < 0 || cfg.Monitor >= len(displays) {
		return fmt.Errorf("monitor %d poza zakresem", cfg.Monitor)
	}
	var td capture.ThreadDesktop
	defer td.Close()
	_, _ = td.Attach()
	dup, err := capture.OpenDuplicator(displays[cfg.Monitor])
	if err != nil {
		return err
	}
	dup.Close()
	return nil
}

// goProbeThread uruchamia pętlę sondy na własnym wątku systemowym: SetThreadDesktop zmienia pulpit wątku na stałe, więc
// wątek nie wraca do puli (gorutyna kończy się bez UnlockOSThread, a Go wtedy niszczy wątek).
func goProbeThread(f func()) {
	go func() {
		runtime.LockOSThread()
		if err := com.InitMTA(); err == nil {
			defer com.Uninit()
		}
		f()
	}()
}

func (e *Engine) count(n int, key bool) {
	e.mu.Lock()
	e.stats.Frames++
	e.stats.Bytes += int64(n)
	if key {
		e.stats.KeyFrames++
	}
	e.mu.Unlock()
}

func (e *Engine) noteError(err error) {
	e.mu.Lock()
	e.stats.LastError = err.Error()
	e.mu.Unlock()
}

// Run działa do anulowania ctx. Awaria ścieżki powoduje zejście na kolejną (gpu → cpu → gdi), a po wyczerpaniu
// ścieżek odczekanie i ponowną próbę od początku (np. po powrocie z ekranu blokady albo zmianie rozdzielczości).
func (e *Engine) Run(ctx context.Context, sink Sink) error {
	// Wątek zostaje zablokowany do końca gorutyny (bez UnlockOSThread): SetThreadDesktop zmienia jego pulpit na stałe, więc
	// Go ma wątek zniszczyć, a nie oddać do puli innym gorutynom. Uchwyt pulpitu żyje do końca procesu pomocnika (jedna sesja).
	runtime.LockOSThread()
	if err := com.InitMTA(); err != nil {
		return err
	}
	defer com.Uninit()
	if err := mf.Startup(); err != nil {
		return err
	}
	defer mf.Shutdown()
	if name, err := e.attachDesktop(); err != nil {
		e.log.Debug("dołączenie do pulpitu wejściowego nieudane", "input_desktop", name, "err", err)
	}

	l := newPathLoop()
	l.log = e.log
	l.config = e.Config
	l.gen = e.gen.Load
	l.run = func(ctx context.Context, cfg Config, path string, gen int64) error {
		err := e.runPath(ctx, sink, cfg, path, gen)
		if err != nil && !errors.Is(err, errRestart) && ctx.Err() == nil {
			e.noteError(err)
		}
		return err
	}
	l.probe = e.probeDXGI
	l.goProbe = goProbeThread
	l.reason = e.setReason
	l.loop(ctx)
	return nil
}

func (e *Engine) runPath(ctx context.Context, sink Sink, cfg Config, path string, gen int64) error {
	displays, err := capture.ListDisplays()
	if err != nil {
		return err
	}
	if cfg.Monitor < 0 || cfg.Monitor >= len(displays) {
		return fmt.Errorf("monitor %d poza zakresem (jest %d)", cfg.Monitor, len(displays))
	}
	disp := displays[cfg.Monitor]
	// Koder H.264 wymaga parzystych wymiarów; przy nieparzystym monitorze gubimy jeden rząd lub kolumnę pikseli.
	w, h := disp.Width()&^1, disp.Height()&^1
	if w < 16 || h < 16 {
		return fmt.Errorf("monitor %d ma zły rozmiar %dx%d", cfg.Monitor, disp.Width(), disp.Height())
	}
	switch path {
	case PathGPU:
		return e.runGPU(ctx, sink, cfg, disp, w, h, gen)
	case PathCPU, PathGDI:
		return e.runCPU(ctx, sink, cfg, disp, w, h, path == PathGDI, gen)
	}
	return fmt.Errorf("nieznana ścieżka %q", path)
}

// restartWanted mówi, czy od startu pętli przyszło Reconfigure.
func (e *Engine) restartWanted(gen int64) bool { return e.gen.Load() != gen }

// pacer ogranicza przechwytywanie do zadanej liczby klatek na sekundę.
type pacer struct {
	period time.Duration
	last   time.Time
}

func (p *pacer) wait() {
	if d := time.Until(p.last.Add(p.period)); d > 0 {
		time.Sleep(d)
	}
}

func (p *pacer) mark() { p.last = time.Now() }

// emitPointer przekazuje ujściu zmiany kursora, jeśli były.
func emitPointer(src capture.Source, sink Sink) {
	if ps, ok := src.(capture.PointerSource); ok {
		if p, ok := ps.Pointer(); ok {
			sink.Pointer(p)
		}
	}
}

// runCPU to ścieżka z kopią klatki do pamięci procesu: DXGI (albo GDI) → BGRAToNV12 w Go → dowolny koder MFT.
func (e *Engine) runCPU(ctx context.Context, sink Sink, cfg Config, disp capture.Display, w, h int, gdi bool, gen int64) error {
	open := func() (capture.Source, error) {
		if gdi {
			return capture.OpenGDI(int(disp.Left), int(disp.Top), disp.Width(), disp.Height())
		}
		return capture.OpenDuplicator(disp)
	}
	pol := openRetry
	if gdi {
		pol.Attempts = 1
	}
	src, err := retryOpen(ctx, pol, e.log, "otwarcie źródła obrazu", e.attachDesktop, open, transientOpenError, func() bool { return e.restartWanted(gen) })
	if err != nil {
		return err
	}
	defer func() { src.Close() }()

	enc, err := mf.NewEncoder(mf.Config{Width: w, Height: h, FPS: cfg.FPS, BitrateKbps: cfg.Kbps, Prefer: cfg.Encoder, VendorID: disp.VendorID})
	if err != nil {
		return fmt.Errorf("koder: %w", err)
	}
	defer enc.Close()
	path := PathCPU
	if gdi {
		path = PathGDI
	}
	e.setInfo(enc.Info.Name, path, w, h, cfg.FPS)
	e.log.Info("silnik pulpitu", "path", path, "encoder", enc.Info.Name, "size", fmt.Sprintf("%dx%d@%d", w, h, cfg.FPS), "kbps", cfg.Kbps, "monitor", cfg.Monitor)
	for _, n := range enc.Notes {
		e.log.Debug("koder", "note", n)
	}

	period := time.Second / time.Duration(cfg.FPS)
	pc := pacer{period: period}
	start := time.Now()
	rtpBase := rand.Uint32()
	nv12 := make([]byte, w*h*3/2)
	var raw []byte
	haveFrame := false
	lastSent := time.Now()
	enc.ForceKeyFrame()

	for ctx.Err() == nil {
		if e.restartWanted(gen) {
			return errRestart
		}
		pc.wait()
		f, err := src.Grab(100, raw)
		capMs := proc.WallMs()
		keepalive := false
		switch {
		case err == nil:
			pc.mark()
			raw = f.Pix
		case errors.Is(err, capture.ErrTimeout):
			emitPointer(src, sink)
			if haveFrame && time.Since(lastSent) > 500*time.Millisecond {
				keepalive = true // ekran stoi: powtórz klatkę, żeby nowy widz dostał obraz, a NAT nie zasnął
			} else if !haveFrame && time.Since(start) > 2*time.Second {
				keepalive = true
			} else {
				continue
			}
		case errors.Is(err, capture.ErrAccessLost):
			e.mu.Lock()
			e.stats.AccessLost++
			e.mu.Unlock()
			e.log.Info("utracono dostęp do pulpitu, ponawiam", "err", err)
			src.Close()
			for ctx.Err() == nil {
				time.Sleep(250 * time.Millisecond)
				if e.restartWanted(gen) {
					return errRestart
				}
				name, _ := e.attachDesktop()
				ns, oerr := open()
				if oerr == nil {
					src = ns
					break
				}
				e.log.Debug("ponowne otwarcie źródła obrazu nieudane", "input_desktop", name, "err", oerr)
			}
			haveFrame = false
			enc.ForceKeyFrame()
			continue
		default:
			return err
		}
		if !keepalive {
			if f.Width < w || f.Height < h {
				return fmt.Errorf("klatka %dx%d mniejsza niż kodowany obszar %dx%d", f.Width, f.Height, w, h)
			}
			mf.BGRAToNV12(nv12, w, h, f.Pix, f.Stride, cfg.Workers)
			haveFrame = true
			emitPointer(src, sink)
		}
		if e.keyReq.Swap(false) {
			enc.ForceKeyFrame()
		}
		res, err := enc.Encode(nv12, time.Since(start), period)
		if err != nil {
			return fmt.Errorf("kodowanie: %w", err)
		}
		if res == nil {
			continue
		}
		rtpTS := rtpBase + uint32(time.Since(start).Seconds()*90000)
		if err := sink.WriteFrame(res.Data, res.Key, rtpTS, capMs); err != nil {
			return fmt.Errorf("wysyłanie: %w", err)
		}
		lastSent = time.Now()
		e.count(len(res.Data), res.Key)
	}
	return nil
}

// runGPU to ścieżka bez kopii przez procesor: tekstura DXGI → ID3D11VideoProcessor (BGRA→NV12) → koder sprzętowy
// na tym samym urządzeniu D3D11. Wymaga kodera sprzętowego na karcie, która wyświetla monitor.
func (e *Engine) runGPU(ctx context.Context, sink Sink, cfg Config, disp capture.Display, w, h int, gen int64) error {
	dev, dctx, err := capture.CreateDevice(disp.AdapterIdx, 0x800|0x20) // VIDEO_SUPPORT | BGRA_SUPPORT
	if err != nil {
		return fmt.Errorf("urządzenie D3D11: %w", err)
	}
	defer com.Release(dctx)
	defer com.Release(dev)
	capture.EnableMultithread(dev)

	dup, err := retryOpen(ctx, openRetry, e.log, "duplikacja", e.attachDesktop, func() (*capture.Duplicator, error) { return capture.OpenDuplicatorOn(disp, dev, dctx) }, transientOpenError, func() bool { return e.restartWanted(gen) })
	if err != nil {
		return err
	}
	defer func() { dup.Close() }()
	sw, sh := dup.Size()
	if w > sw || h > sh {
		return fmt.Errorf("monitor ma %dx%d, a kodujemy %dx%d", sw, sh, w, h)
	}
	vp, err := capture.NewVideoProc(dev, dctx, sw, sh, w, h, cfg.FPS, 3)
	if err != nil {
		return fmt.Errorf("procesor wideo: %w", err)
	}
	defer vp.Close()
	enc, err := mf.NewEncoder(mf.Config{Width: w, Height: h, FPS: cfg.FPS, BitrateKbps: cfg.Kbps, Prefer: cfg.Encoder, D3DDevice: dev, VendorID: disp.VendorID, RequireVendor: true})
	if err != nil {
		return fmt.Errorf("koder: %w", err)
	}
	defer enc.Close()
	var samples []*mf.TexSample
	for _, t := range vp.Tex {
		s, err := enc.NewTextureSample(t)
		if err != nil {
			return fmt.Errorf("próbka z tekstury (ścieżka GPU wymaga kodera sprzętowego): %w", err)
		}
		defer s.Release()
		samples = append(samples, s)
	}
	e.setInfo(enc.Info.Name, PathGPU, w, h, cfg.FPS)
	e.log.Info("silnik pulpitu", "path", PathGPU, "encoder", enc.Info.Name, "size", fmt.Sprintf("%dx%d@%d", w, h, cfg.FPS), "kbps", cfg.Kbps, "monitor", cfg.Monitor)
	for _, n := range enc.Notes {
		e.log.Debug("koder", "note", n)
	}

	period := time.Second / time.Duration(cfg.FPS)
	pc := pacer{period: period}
	start := time.Now()
	rtpBase := rand.Uint32()
	lastIdx := -1
	lastSent := time.Now()
	enc.ForceKeyFrame()

	for ctx.Err() == nil {
		if e.restartWanted(gen) {
			return errRestart
		}
		pc.wait()
		f, err := dup.AcquireTexture(100)
		capMs := proc.WallMs()
		keepalive := false
		var cur int
		switch {
		case err == nil:
			pc.mark()
		case errors.Is(err, capture.ErrTimeout):
			emitPointer(dup, sink)
			if lastIdx >= 0 && time.Since(lastSent) > 500*time.Millisecond {
				keepalive = true
			} else if lastIdx < 0 && time.Since(start) > time.Second {
				// Ekran bez zmian od startu: DXGI nie oddał jeszcze żadnej tekstury, a widz czeka na pierwszy obraz.
				// Jednorazowo bierzemy zrzut GDI i wgrywamy go jako teksturę wejściową procesora wideo.
				idx, uerr := uploadSnapshot(dev, vp, disp)
				if uerr != nil {
					e.log.Debug("pierwsza klatka ze zrzutu GDI nieudana", "err", uerr)
					time.Sleep(500 * time.Millisecond)
					continue
				}
				lastIdx = idx
				cur = idx
				enc.ForceKeyFrame()
				goto encode
			} else {
				continue
			}
		case errors.Is(err, capture.ErrAccessLost):
			e.mu.Lock()
			e.stats.AccessLost++
			e.mu.Unlock()
			e.log.Info("utracono dostęp do pulpitu, ponawiam", "err", err)
			dup.Close()
			for ctx.Err() == nil {
				time.Sleep(250 * time.Millisecond)
				if e.restartWanted(gen) {
					return errRestart
				}
				name, _ := e.attachDesktop()
				nd, oerr := capture.OpenDuplicatorOn(disp, dev, dctx)
				if oerr == nil {
					dup = nd
					break
				}
				e.log.Debug("ponowne otwarcie duplikacji nieudane", "input_desktop", name, "err", oerr)
			}
			lastIdx = -1
			enc.ForceKeyFrame()
			continue
		default:
			return err
		}
		cur = lastIdx
		if !keepalive {
			cur, err = vp.Convert(f.Tex)
			dup.ReleaseTexture(&f)
			if err != nil {
				return err
			}
			lastIdx = cur
			emitPointer(dup, sink)
		}
	encode:
		if e.keyReq.Swap(false) {
			enc.ForceKeyFrame()
		}
		res, err := enc.EncodeSample(samples[cur], time.Since(start), period)
		if err != nil {
			return fmt.Errorf("kodowanie: %w", err)
		}
		if res == nil {
			continue
		}
		rtpTS := rtpBase + uint32(time.Since(start).Seconds()*90000)
		if err := sink.WriteFrame(res.Data, res.Key, rtpTS, capMs); err != nil {
			return fmt.Errorf("wysyłanie: %w", err)
		}
		lastSent = time.Now()
		e.count(len(res.Data), res.Key)
	}
	return nil
}

// uploadSnapshot robi zrzut GDI monitora, wgrywa go jako teksturę i przepuszcza przez procesor wideo; zwraca indeks
// tekstury wyjściowej NV12.
func uploadSnapshot(dev *com.Object, vp *capture.VideoProc, disp capture.Display) (int, error) {
	g, err := capture.OpenGDI(int(disp.Left), int(disp.Top), disp.Width(), disp.Height())
	if err != nil {
		return 0, err
	}
	defer g.Close()
	f, err := g.Grab(0, nil)
	if err != nil {
		return 0, err
	}
	tex, err := capture.UploadBGRA(dev, f.Pix, f.Stride, f.Width, f.Height)
	if err != nil {
		return 0, err
	}
	defer com.Release(tex)
	return vp.Convert(tex)
}

// Displays zwraca listę monitorów w kolejności indeksów używanych w Config.Monitor.
func Displays() ([]capture.Display, error) { return capture.ListDisplays() }
