//go:build windows

// Package helper to pętla procesu pomocnika pulpitu: czyta komunikaty usługi ze standardowego wejścia, prowadzi jedną
// sesję WebRTC i odsyła odpowiedź, kandydatów oraz stan na standardowe wyjście (agent/internal/ipc, DesktopMsg).
// Jeden proces obsługuje jedną sesję: po jej końcu kończy się, a następną uruchamia usługa od nowa.
package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/engine"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/peer"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/winput"
	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// StartTimeout to czas oczekiwania na komunikat start po ready; bez niego pomocnik kończy się sam.
const StartTimeout = 60 * time.Second

// Helper to stan jednego procesu pomocnika.
type Helper struct {
	in      *bufio.Reader
	out     io.Writer
	outMu   sync.Mutex
	log     *slog.Logger
	version string

	mu      sync.Mutex
	session *peer.Session
	// pauseTimer wznawia wejście po pauzie, gdy usługa nie przysłała DesktopResume.
	pauseTimer *time.Timer
	inj        *peer.ThreadInjector
	done       chan struct{}
}

// New tworzy pomocnika czytającego z in i piszącego do out. Dziennik idzie do usługi komunikatami log.
func New(in io.Reader, out io.Writer, version string) *Helper {
	h := &Helper{in: bufio.NewReaderSize(in, 1<<20), out: out, version: version, done: make(chan struct{})}
	h.log = slog.New(&logHandler{h: h, level: slog.LevelInfo})
	return h
}

// Run obsługuje komunikaty do końca sesji albo zamknięcia wejścia. Zwraca nil po normalnym końcu.
func (h *Helper) Run(ctx context.Context) error {
	proc.SetDPIAware()
	proc.HighResTimer()
	// Kontekst procesu do dziennika od razu przy starcie: token, poziom integralności i pulpity (CreateProcessAsUser z usługi
	// potrafi dać inny kontekst niż zwykłe uruchomienie).
	h.log.Info("pomocnik uruchomiony", "version", h.version, "context", winput.Context().String())
	displays, err := capture.ListDisplays()
	if err != nil {
		h.send(ipc.DesktopMsg{Kind: ipc.DesktopState, State: ipc.StateFailed, Error: "lista monitorów: " + err.Error()})
		return err
	}
	ready := ipc.DesktopMsg{Kind: ipc.DesktopReady, Version: h.version}
	for i, d := range displays {
		ready.Displays = append(ready.Displays, ipc.DesktopDisplay{Index: i, Name: d.DeviceName, Width: d.Width(), Height: d.Height(), Left: int(d.Left), Top: int(d.Top), Primary: d.Left == 0 && d.Top == 0})
	}
	h.send(ready)

	msgs := make(chan ipc.DesktopMsg)
	readErr := make(chan error, 1)
	go func() {
		for {
			var m ipc.DesktopMsg
			if err := ipc.ReadLine(h.in, &m); err != nil {
				readErr <- err
				return
			}
			msgs <- m
		}
	}()

	startTimer := time.NewTimer(StartTimeout)
	defer startTimer.Stop()
	started := false
	for {
		select {
		case <-ctx.Done():
			h.stop()
			return nil
		case <-h.done:
			return nil
		case err := <-readErr:
			// Usługa zamknęła potok (koniec sesji albo awaria usługi): sesja nie może żyć bez nadzoru.
			h.stop()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-startTimer.C:
			if !started {
				return errors.New("brak komunikatu start w czasie " + StartTimeout.String())
			}
		case m := <-msgs:
			switch m.Kind {
			case ipc.DesktopStart:
				if started {
					h.send(ipc.DesktopMsg{Kind: ipc.DesktopState, SessionID: m.SessionID, State: ipc.StateFailed, Error: "sesja już trwa"})
					continue
				}
				started = true
				startTimer.Stop()
				if err := h.start(m, displays); err != nil {
					h.send(ipc.DesktopMsg{Kind: ipc.DesktopState, SessionID: m.SessionID, State: ipc.StateFailed, Error: err.Error()})
					return err
				}
			case ipc.DesktopSignal:
				h.mu.Lock()
				s := h.session
				h.mu.Unlock()
				if s != nil && m.Candidate != "" {
					if err := s.AddCandidate(m.Candidate, m.SDPMid); err != nil {
						h.log.Debug("kandydat ICE odrzucony", "err", err)
					}
				}
			case ipc.DesktopPause, ipc.DesktopResume:
				h.pauseInput(m.Kind == ipc.DesktopPause)
			case ipc.DesktopStop:
				h.stop()
				return nil
			}
		}
	}
}

// pauseTimeout to najdłuższa pauza wejścia: jeśli usługa nie przyśle DesktopResume (padła, zgubiony komunikat), pomocnik sam wznawia, żeby
// sterowanie nie zostało wyłączone na zawsze.
const pauseTimeout = 75 * time.Second

// pauseInput wstrzymuje albo wznawia wstrzykiwanie wejścia w bieżącej sesji (pytanie użytkownika o zgodę trwa).
func (h *Helper) pauseInput(on bool) {
	h.mu.Lock()
	s := h.session
	if h.pauseTimer != nil {
		h.pauseTimer.Stop()
		h.pauseTimer = nil
	}
	if on && s != nil {
		h.pauseTimer = time.AfterFunc(pauseTimeout, func() { h.pauseInput(false) })
	}
	h.mu.Unlock()
	if s != nil {
		s.PauseInput(on)
	}
}

func (h *Helper) start(m ipc.DesktopMsg, displays []capture.Display) error {
	if m.SDP == "" {
		return errors.New("start bez oferty SDP")
	}
	mon := m.Monitor
	if mon < 0 || mon >= len(displays) {
		mon = 0
	}
	fps := m.FPS
	if fps == 0 {
		fps = engine.DefaultFPS
	}
	eng := engine.New(engine.Config{Monitor: mon, FPS: fps}, h.log)
	var inj peer.Injector
	var winj *winput.Injector
	var probe func() (any, any)
	stats := &peer.InputStats{}
	if m.Control {
		winj = injectorFor(displays[mon])
		// Kontrola po każdym ruchu myszy: kursor ma być tam, dokąd go wysłano. Rozbieżność przy sukcesie SendInput to ślad
		// po cichym odrzuceniu wejścia (UIPI, zły pulpit).
		winj.Check = func(wx, wy, gx, gy int) {
			if absInt(wx-gx) > 2 || absInt(wy-gy) > 2 {
				stats.NoteMismatch(fmt.Sprintf("cel (%d,%d), kursor (%d,%d)", wx, wy, gx, gy))
			}
		}
		// Całe wstrzykiwanie na jednym przypiętym wątku dołączonym do pulpitu wejściowego (SendInput działa na pulpicie wątku).
		ti := peer.NewThreadInjector(winj, h.log)
		h.mu.Lock()
		h.inj = ti
		h.mu.Unlock()
		inj = ti
		probe = ti.Probe
	}
	sessionID := m.SessionID
	var infos []peer.DisplayInfo
	for i, d := range displays {
		infos = append(infos, peer.DisplayInfo{Index: i, Name: d.DeviceName, Width: d.Width(), Height: d.Height(), Primary: d.Left == 0 && d.Top == 0})
	}
	s, err := peer.New(peer.Options{
		ICEServers:        m.ICEServers,
		Engine:            eng,
		Injector:          inj,
		Input:             stats,
		Probe:             probe,
		Log:               h.log,
		Displays:          infos,
		RemoteFingerprint: m.Fingerprint,
		OnState: func(state string, st wire.RemoteStats) {
			h.send(ipc.DesktopMsg{Kind: ipc.DesktopState, SessionID: sessionID, State: state, Stats: &st})
			if state != peer.StateConnected {
				h.finish()
			}
		},
		OnCandidate: func(c, mid string) {
			h.send(ipc.DesktopMsg{Kind: ipc.DesktopCandidate, SessionID: sessionID, Candidate: c, SDPMid: mid})
		},
		OnConfig: func(monitor, _ *int) {
			// Po zmianie monitora współrzędne 0..1 widza odnoszą się do nowego monitora.
			if monitor != nil && winj != nil && *monitor >= 0 && *monitor < len(displays) {
				d := displays[*monitor]
				winj.SetMonitor(int(d.Left), int(d.Top), d.Width()&^1, d.Height()&^1)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("sesja WebRTC: %w", err)
	}
	h.mu.Lock()
	h.session = s
	h.mu.Unlock()
	answer, fp, err := s.Answer(m.SDP)
	if err != nil {
		s.Close()
		return err
	}
	h.send(ipc.DesktopMsg{Kind: ipc.DesktopAnswer, SessionID: sessionID, SDP: answer, Fingerprint: fp})
	return nil
}

// injectorFor mapuje współrzędne 0..1 na cały monitor (kodowany jest cały monitor, przycięty do parzystych wymiarów).
func injectorFor(d capture.Display) *winput.Injector {
	return &winput.Injector{MonLeft: int(d.Left), MonTop: int(d.Top), MonW: d.Width() &^ 1, MonH: d.Height() &^ 1}
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (h *Helper) stop() {
	h.mu.Lock()
	s := h.session
	h.session = nil
	h.mu.Unlock()
	if s != nil {
		s.Close()
	}
	h.finish()
}

func (h *Helper) finish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inj != nil {
		h.inj.Close()
		h.inj = nil
	}
	select {
	case <-h.done:
	default:
		close(h.done)
	}
}

func (h *Helper) send(m ipc.DesktopMsg) {
	h.outMu.Lock()
	defer h.outMu.Unlock()
	_ = ipc.WriteLine(h.out, m)
}

// logHandler zamienia wpisy slog na komunikaty log do usługi (pomocnik nie ma własnego pliku dziennika).
type logHandler struct {
	h     *Helper
	level slog.Level
	attrs []slog.Attr
}

func (l *logHandler) Enabled(_ context.Context, lv slog.Level) bool { return lv >= l.level }

func (l *logHandler) Handle(_ context.Context, r slog.Record) error {
	text := r.Message
	add := func(a slog.Attr) bool {
		text += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	}
	for _, a := range l.attrs {
		add(a)
	}
	r.Attrs(add)
	l.h.send(ipc.DesktopMsg{Kind: ipc.DesktopLog, Level: r.Level.String(), Text: text})
	return nil
}

func (l *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logHandler{h: l.h, level: l.level, attrs: append(append([]slog.Attr{}, l.attrs...), attrs...)}
}

func (l *logHandler) WithGroup(string) slog.Handler { return l }

// Probe wypisuje monitory i kodery (narzędzie diagnostyczne na komputerze klienta: `desktop-helper probe`).
func Probe(w io.Writer) error {
	proc.SetDPIAware()
	displays, err := capture.ListDisplays()
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "Monitory:")
	for i, d := range displays {
		fmt.Fprintf(w, "  %d: %s %dx%d @(%d,%d) karta=%s\n", i, d.DeviceName, d.Width(), d.Height(), d.Left, d.Top, d.AdapterName)
	}
	if _, err := fmt.Fprintln(w, "Kodery H.264: sprawdzane przy starcie sesji (Media Foundation)."); err != nil {
		return err
	}
	return nil
}

// Stdio zwraca standardowe wejście i wyjście procesu (osobno, żeby main nie musiał znać os).
func Stdio() (io.Reader, io.Writer) { return os.Stdin, os.Stdout }
