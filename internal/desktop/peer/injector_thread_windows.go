//go:build windows

package peer

import (
	"errors"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/winput"
)

// Parametry wątku wstrzykiwania.
const (
	// reattachEvery: co ile wątek ponownie dołącza do pulpitu wejściowego (pulpit wejściowy potrafi się zmienić w trakcie sesji:
	// blokada, UAC, przełączenie użytkownika); koszt to jedno OpenInputDesktop + SetThreadDesktop.
	reattachEvery = time.Second
	// injectCallTimeout: jak długo wywołujący (kanał danych) czeka na wątek wstrzykiwania, zanim uzna go za zawieszony.
	injectCallTimeout = 2 * time.Second
)

// ErrInjectorClosed: wątek wstrzykiwania został zatrzymany.
var ErrInjectorClosed = errors.New("peer: wątek wstrzykiwania zatrzymany")

type injectJob struct {
	fn  func() error
	res chan error
}

// ThreadInjector wykonuje całe wstrzykiwanie na jednym, przypiętym wątku systemowym (runtime.LockOSThread), który przed
// zdarzeniami dołącza do pulpitu WEJŚCIOWEGO (OpenInputDesktop + SetThreadDesktop). SendInput działa na pulpicie wątku
// wołającego, a callbacki kanałów danych (pion) biegną na dowolnych wątkach Go, więc bez tego wejście zależy od tego, na
// który wątek trafi gorutyna. Zdarzenia są szeregowane (jedno po drugim, w kolejności wywołań); po błędzie SendInput wątek
// dołącza do pulpitu jeszcze raz i ponawia zdarzenie jednokrotnie.
type ThreadInjector struct {
	inner Injector
	log   *slog.Logger

	jobs chan injectJob
	done chan struct{}
	once sync.Once

	// attach dołącza wątek do pulpitu wejściowego i zwraca jego nazwę; podmieniane w testach.
	attach func() (string, error)
	// callTimeout i reattach pozwalają testom skrócić czasy.
	callTimeout time.Duration
	reattach    time.Duration

	threadID  atomic.Uint32
	desktop   atomic.Value // string: pulpit, do którego wątek dołączył ostatnio
	attaches  atomic.Int64
	attachErr atomic.Int64
}

// NewThreadInjector uruchamia wątek wstrzykiwania dla inner. Close zatrzymuje go i kończy wątek systemowy.
func NewThreadInjector(inner Injector, log *slog.Logger) *ThreadInjector {
	if log == nil {
		log = slog.Default()
	}
	t := &ThreadInjector{inner: inner, log: log, jobs: make(chan injectJob), done: make(chan struct{}), callTimeout: injectCallTimeout, reattach: reattachEvery}
	var td capture.ThreadDesktop
	t.attach = td.Attach
	ready := make(chan struct{})
	go t.pump(ready)
	<-ready
	return t
}

// ThreadID zwraca identyfikator wątku systemowego, na którym działa wstrzykiwanie (do testów i diagnostyki).
func (t *ThreadInjector) ThreadID() uint32 { return t.threadID.Load() }

// Desktop zwraca nazwę pulpitu, do którego wątek dołączył ostatnio.
func (t *ThreadInjector) Desktop() string {
	if v, ok := t.desktop.Load().(string); ok {
		return v
	}
	return ""
}

func (t *ThreadInjector) pump(ready chan<- struct{}) {
	// Brak UnlockOSThread: SetThreadDesktop zmienia pulpit wątku na stałe, więc Go ma wątek zniszczyć po zakończeniu gorutyny.
	runtime.LockOSThread()
	t.threadID.Store(windows.GetCurrentThreadId())
	var lastAttach time.Time
	attach := func(why string) {
		name, err := t.attach()
		lastAttach = time.Now()
		t.attaches.Add(1)
		if err != nil {
			t.attachErr.Add(1)
			t.log.Warn("wątek wstrzykiwania: dołączenie do pulpitu wejściowego nieudane", "why", why, "input_desktop", name, "err", err)
			return
		}
		prev, _ := t.desktop.Load().(string)
		t.desktop.Store(name)
		if prev != name {
			t.log.Info("wątek wstrzykiwania dołączony do pulpitu wejściowego", "desktop", name, "thread_id", t.threadID.Load(), "why", why)
		}
	}
	attach("start")
	close(ready)
	for {
		select {
		case <-t.done:
			return
		case j := <-t.jobs:
			if time.Since(lastAttach) > t.reattach {
				attach("odświeżenie")
			}
			err := j.fn()
			var sie *winput.SendInputError
			if err != nil && errors.As(err, &sie) {
				// Pulpit wejściowy mógł się zmienić od ostatniego dołączenia: dołączamy jeszcze raz i ponawiamy to zdarzenie.
				attach("po błędzie SendInput")
				if err2 := j.fn(); err2 == nil {
					err = nil
				} else {
					err = err2
				}
			}
			j.res <- err
		}
	}
}

// do wykonuje fn na wątku wstrzykiwania i czeka na wynik (z limitem czasu).
func (t *ThreadInjector) do(fn func() error) error {
	if t == nil {
		return ErrInjectorClosed
	}
	j := injectJob{fn: fn, res: make(chan error, 1)}
	timeout := time.NewTimer(t.callTimeout)
	defer timeout.Stop()
	select {
	case t.jobs <- j:
	case <-t.done:
		return ErrInjectorClosed
	case <-timeout.C:
		return errors.New("peer: wątek wstrzykiwania nie odpowiada (zajęty albo zawieszony)")
	}
	select {
	case err := <-j.res:
		return err
	case <-t.done:
		return ErrInjectorClosed
	case <-timeout.C:
		return errors.New("peer: wątek wstrzykiwania nie odpowiedział w czasie")
	}
}

// Move, Button, Wheel i Key implementują Injector na wątku wstrzykiwania.
func (t *ThreadInjector) Move(nx, ny float64) error {
	return t.do(func() error { return t.inner.Move(nx, ny) })
}
func (t *ThreadInjector) Button(b int, down bool) error {
	return t.do(func() error { return t.inner.Button(b, down) })
}
func (t *ThreadInjector) Wheel(dx, dy int) error {
	return t.do(func() error { return t.inner.Wheel(dx, dy) })
}
func (t *ThreadInjector) Key(code string, down bool) error {
	return t.do(func() error { return t.inner.Key(code, down) })
}

// Probe czyta kontekst procesu i okno na pierwszym planie NA wątku wstrzykiwania, więc pulpit wątku w wyniku to pulpit,
// na którym naprawdę działa SendInput.
func (t *ThreadInjector) Probe() (proc any, fg any) {
	var c winput.ProcessContext
	var f winput.ForegroundInfo
	if err := t.do(func() error {
		c = winput.Context()
		f = winput.Foreground(c.IntegrityRID)
		return nil
	}); err != nil {
		return map[string]string{"error": err.Error()}, nil
	}
	return c, f
}

// Close zatrzymuje wątek wstrzykiwania (idempotentne).
func (t *ThreadInjector) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() { close(t.done) })
}
