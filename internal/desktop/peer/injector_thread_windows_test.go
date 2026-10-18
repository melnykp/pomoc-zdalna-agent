//go:build windows

package peer

import (
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/winput"
)

// threadProbe zapisuje wątek systemowy i pulpit wątku przy każdym wywołaniu Key.
type threadProbe struct {
	mu       sync.Mutex
	threads  map[uint32]int
	desktops map[string]int
	calls    int
	failKey  func(call int) error
}

func newThreadProbe() *threadProbe {
	return &threadProbe{threads: map[uint32]int{}, desktops: map[string]int{}}
}

func (p *threadProbe) Move(float64, float64) error { return p.note() }
func (p *threadProbe) Button(int, bool) error      { return p.note() }
func (p *threadProbe) Wheel(int, int) error        { return p.note() }
func (p *threadProbe) Key(string, bool) error      { return p.note() }
func (p *threadProbe) note() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.threads[windows.GetCurrentThreadId()]++
	p.desktops[winput.ThreadDesktopName()]++
	if p.failKey != nil {
		return p.failKey(p.calls)
	}
	return nil
}

func TestThreadInjectorRunsEverythingOnOnePinnedThreadAttachedToInputDesktop(t *testing.T) {
	probe := newThreadProbe()
	ti := NewThreadInjector(probe, quietLogger())
	defer ti.Close()

	// Wołania z wielu gorutyn naraz (tak działają callbacki kanałów danych pion).
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := ti.Key("KeyA", i%2 == 0); err != nil {
					t.Error(err)
					return
				}
				_ = ti.Move(0.5, 0.5)
			}
		}()
	}
	wg.Wait()

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.threads) != 1 {
		t.Fatalf("wstrzykiwanie na %d wątkach systemowych: %v (oczekiwano jednego)", len(probe.threads), probe.threads)
	}
	if _, ok := probe.threads[ti.ThreadID()]; !ok || ti.ThreadID() == 0 {
		t.Fatalf("wątek wstrzykiwania %d nie jest wątkiem wywołań %v", ti.ThreadID(), probe.threads)
	}
	if probe.calls != 8*25*2 {
		t.Fatalf("wykonano %d wywołań z 400", probe.calls)
	}
	// Pulpit wątku to pulpit wejściowy (na tym komputerze „Default”; gdy wejściowego nie da się odczytać, tylko niepusty).
	in, err := winput.InputDesktopName()
	for d := range probe.desktops {
		if d == "" {
			t.Fatalf("pulpit wątku wstrzykiwania pusty: %v", probe.desktops)
		}
		if err == nil && d != in {
			t.Fatalf("pulpit wątku %q ≠ pulpit wejściowy %q", d, in)
		}
	}
	if ti.Desktop() == "" {
		t.Fatal("wątek nie zgłosił pulpitu, do którego dołączył")
	}
}

func TestThreadInjectorReattachesAndRetriesOnceAfterSendInputError(t *testing.T) {
	probe := newThreadProbe()
	probe.failKey = func(call int) error {
		if call == 1 {
			return &winput.SendInputError{Op: "klawisz", Errno: syscall.ERROR_ACCESS_DENIED, ThreadDesktop: "Default", InputDesktop: "Winlogon"}
		}
		return nil
	}
	ti := NewThreadInjector(probe, quietLogger())
	defer ti.Close()
	before := ti.attaches.Load()
	if err := ti.Key("KeyA", true); err != nil {
		t.Fatalf("zdarzenie powinno przejść po ponownym dołączeniu: %v", err)
	}
	if got := ti.attaches.Load() - before; got != 1 {
		t.Fatalf("ponownych dołączeń: %d, oczekiwano 1", got)
	}
	probe.mu.Lock()
	calls := probe.calls
	probe.mu.Unlock()
	if calls != 2 {
		t.Fatalf("wywołań SendInput: %d, oczekiwano 2 (próba i jedno ponowienie)", calls)
	}

	// Trwały błąd: jedno ponowienie, potem błąd do wołającego (nie pętla w nieskończoność).
	probe2 := newThreadProbe()
	probe2.failKey = func(int) error {
		return &winput.SendInputError{Op: "mysz", Errno: syscall.ERROR_ACCESS_DENIED}
	}
	ti2 := NewThreadInjector(probe2, quietLogger())
	defer ti2.Close()
	err := ti2.Move(0.1, 0.1)
	var sie *winput.SendInputError
	if !errors.As(err, &sie) || !sie.IsAccessDenied() {
		t.Fatalf("błąd %v", err)
	}
	if probe2.calls != 2 {
		t.Fatalf("trwały błąd: %d wywołań, oczekiwano 2", probe2.calls)
	}

	// Błąd inny niż SendInput (np. nieznany klawisz) nie wywołuje ponowienia.
	probe3 := newThreadProbe()
	probe3.failKey = func(int) error { return errors.New("nieznany klawisz") }
	ti3 := NewThreadInjector(probe3, quietLogger())
	defer ti3.Close()
	if err := ti3.Key("Dziwny", true); err == nil || probe3.calls != 1 {
		t.Fatalf("błąd %v, wywołań %d (oczekiwano 1 bez ponowienia)", err, probe3.calls)
	}
}

func TestThreadInjectorPeriodicallyReattachesToFollowDesktopSwitches(t *testing.T) {
	probe := newThreadProbe()
	ti := NewThreadInjector(probe, quietLogger())
	defer ti.Close()
	ti.reattach = 20 * time.Millisecond
	before := ti.attaches.Load()
	for i := 0; i < 5; i++ {
		_ = ti.Key("KeyA", true)
		time.Sleep(30 * time.Millisecond)
	}
	if got := ti.attaches.Load() - before; got < 3 {
		t.Fatalf("okresowych dołączeń: %d, oczekiwano co najmniej 3", got)
	}
}

func TestThreadInjectorTimeoutAndClose(t *testing.T) {
	block := make(chan struct{})
	slow := &blockingInjector{block: block}
	ti := NewThreadInjector(slow, quietLogger())
	ti.callTimeout = 100 * time.Millisecond
	start := time.Now()
	err := ti.Key("KeyA", true) // zajmuje wątek
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("zawieszony wątek powinien dać błąd po limicie czasu (błąd %v po %s)", err, time.Since(start))
	}
	if err := ti.Move(0.1, 0.1); err == nil {
		t.Fatal("kolejne wołanie do zajętego wątku też powinno zgłosić błąd, nie zawisnąć")
	}
	close(block)
	ti.Close()
	ti.Close() // idempotentne
	if err := ti.Key("KeyA", true); !errors.Is(err, ErrInjectorClosed) {
		t.Fatalf("po Close: %v", err)
	}
	var nilInj *ThreadInjector
	if err := nilInj.Key("KeyA", true); !errors.Is(err, ErrInjectorClosed) {
		t.Fatalf("nil: %v", err)
	}
}

type blockingInjector struct{ block chan struct{} }

func (b *blockingInjector) Move(float64, float64) error { <-b.block; return nil }
func (b *blockingInjector) Button(int, bool) error      { <-b.block; return nil }
func (b *blockingInjector) Wheel(int, int) error        { <-b.block; return nil }
func (b *blockingInjector) Key(string, bool) error      { <-b.block; return nil }

func TestThreadInjectorProbeReportsContextOfInjectionThread(t *testing.T) {
	ti := NewThreadInjector(newThreadProbe(), quietLogger())
	defer ti.Close()
	proc, fg := ti.Probe()
	c, ok := proc.(winput.ProcessContext)
	if !ok {
		t.Fatalf("kontekst: %#v", proc)
	}
	if _, ok := fg.(winput.ForegroundInfo); !ok {
		t.Fatalf("pierwszy plan: %#v", fg)
	}
	if c.ThreadDesktop == "" || c.ThreadDesktop != ti.Desktop() {
		t.Fatalf("pulpit wątku w kontekście %q ≠ pulpit dołączenia %q", c.ThreadDesktop, ti.Desktop())
	}
}
