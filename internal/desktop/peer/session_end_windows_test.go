//go:build windows

package peer

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/engine"
)

// timedInjector zapisuje chwilę każdego puszczenia, żeby porównać ją z chwilą zatrzymania silnika.
type timedInjector struct {
	mu       sync.Mutex
	released []time.Time
	pressed  int
}

func (t *timedInjector) Move(float64, float64) error { return nil }
func (t *timedInjector) Wheel(int, int) error        { return nil }
func (t *timedInjector) Button(_ int, down bool) error {
	return t.note(down)
}
func (t *timedInjector) Key(_ string, down bool) error { return t.note(down) }
func (t *timedInjector) note(down bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if down {
		t.pressed++
	} else {
		t.released = append(t.released, time.Now())
	}
	return nil
}

// bareSession buduje sesję bez pion: tylko to, czego używa end() i onInput().
func bareSession(inj Injector) *Session {
	eng := engine.New(engine.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &Session{o: Options{Engine: eng, Injector: inj}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), pressd: NewPressed(), inputStats: &InputStats{}}
}

func TestEndReleasesKeysBeforeWaitingForSlowEngine(t *testing.T) {
	inj := &timedInjector{}
	s := bareSession(inj)
	s.onInput([]byte(`{"t":"kd","c":"ControlLeft"}`))
	s.onInput([]byte(`{"t":"md","b":0}`))
	if inj.pressed != 2 {
		t.Fatalf("wciśniętych %d", inj.pressed)
	}
	// Silnik „wolno” kończy pracę: 1 s po anulowaniu.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var engineStopped time.Time
	go func() {
		<-ctx.Done()
		time.Sleep(time.Second)
		engineStopped = time.Now()
		close(done)
	}()
	s.mu.Lock()
	s.started, s.cancel, s.engineDone = true, cancel, done
	s.mu.Unlock()

	t0 := time.Now()
	s.end(StateDisconnected)
	ended := time.Now()

	inj.mu.Lock()
	defer inj.mu.Unlock()
	if len(inj.released) != 2 {
		t.Fatalf("puszczono %d z 2", len(inj.released))
	}
	for _, r := range inj.released {
		if r.Sub(t0) > 200*time.Millisecond {
			t.Fatalf("puszczenie po %s od końca sesji: ma być natychmiastowe, przed czekaniem na silnik", r.Sub(t0))
		}
		if !r.Before(engineStopped) {
			t.Fatal("puszczenie musi nastąpić przed zatrzymaniem silnika")
		}
	}
	if ended.Sub(t0) < 900*time.Millisecond {
		t.Fatalf("end powinien poczekać na silnik (trwało %s)", ended.Sub(t0))
	}
}

func TestInputIsIgnoredAfterEnd(t *testing.T) {
	inj := &timedInjector{}
	s := bareSession(inj)
	s.end(StateDisconnected)
	s.onInput([]byte(`{"t":"kd","c":"KeyA"}`))
	s.onInput([]byte(`{"t":"md","b":0}`))
	if inj.pressed != 0 {
		t.Fatalf("po zakończeniu wstrzyknięto %d zdarzeń", inj.pressed)
	}
	if s.pressd.Count() != 0 {
		t.Fatal("rejestr wciśniętych ma być pusty")
	}
}

// Na czas pytania użytkownika o zgodę wejście od widza jest wstrzymane: wciśnięte klawisze zostają puszczone, kolejne zdarzenia sterujące są
// odrzucane (inżynier nie kliknie w nic obok okna zgody), a po wznowieniu wejście znowu działa. Ping, puszczenie klawiszy i zmiana
// monitora nie są wstrzymywane.
func TestPauseInputDropsControlEventsAndReleasesKeysUntilResumed(t *testing.T) {
	inj := &timedInjector{}
	s := bareSession(inj)
	s.onInput([]byte(`{"t":"kd","c":"ShiftLeft"}`))
	s.onInput([]byte(`{"t":"md","b":0}`))
	if inj.pressed != 2 {
		t.Fatalf("wciśniętych %d", inj.pressed)
	}

	s.PauseInput(true)
	inj.mu.Lock()
	released := len(inj.released)
	inj.mu.Unlock()
	if released != 2 || s.pressd.Count() != 0 {
		t.Fatalf("przy wstrzymaniu klawisze mają zostać puszczone: puszczono %d, wciśniętych %d", released, s.pressd.Count())
	}
	for _, ev := range []string{`{"t":"kd","c":"KeyA"}`, `{"t":"md","b":0}`, `{"t":"mm","x":0.5,"y":0.5}`, `{"t":"wh","dy":120}`} {
		s.onInput([]byte(ev))
	}
	if inj.pressed != 2 {
		t.Fatalf("w czasie pauzy nic nie może zostać wstrzyknięte, a jest %d wciśnięć", inj.pressed)
	}
	if s.inputStats.Rejected.Load() < 4 {
		t.Fatalf("odrzucone zdarzenia mają trafić do statystyk, jest %d", s.inputStats.Rejected.Load())
	}
	// Podwójne wstrzymanie i wznowienie są bezpieczne.
	s.PauseInput(true)
	s.PauseInput(false)
	s.PauseInput(false)
	s.onInput([]byte(`{"t":"kd","c":"KeyA"}`))
	if inj.pressed != 3 {
		t.Fatalf("po wznowieniu wejście działa: %d wciśnięć", inj.pressed)
	}
}
