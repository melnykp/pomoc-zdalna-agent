package engine

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// PathInfo opisuje ścieżkę, na której silnik naprawdę pracuje; widz dostaje to w kanale meta i pokazuje tryb awaryjny.
type PathInfo struct {
	Path string
	// Degraded: obraz idzie wolniejszą ścieżką bez okien warstwowych (GDI), a nie przez duplikację DXGI.
	Degraded bool
	// Reason to skrócony powód zejścia z szybkiej ścieżki (ostatni błąd), pusty na szybkiej ścieżce.
	Reason string
}

// pathLoop wybiera ścieżkę przechwytywania i pilnuje powrotu z awaryjnej. Cała logika jest bez Windows i bez COM, żeby
// dało się ją testować na atrapie (run, probe).
type pathLoop struct {
	log    *slog.Logger
	config func() Config
	gen    func() int64
	// run uruchamia jedną ścieżkę aż do błędu, zakończenia ctx albo sygnału (errRestart, errUpgrade po anulowaniu).
	run func(ctx context.Context, cfg Config, path string, gen int64) error
	// probe sprawdza tanio, czy DXGI da się teraz otworzyć (bez kodowania). Woła ją goProbe na osobnym wątku systemowym.
	probe func() error
	// goProbe uruchamia pętlę sondy; produkcyjnie na zablokowanym wątku systemowym, w testach zwykła gorutyna.
	goProbe func(func())
	// sleep czeka d (false, gdy ctx się skończył); podmieniane w testach.
	sleep func(ctx context.Context, d time.Duration) bool
	now   func() time.Time
	// failed zapamiętuje powód zejścia z szybkiej ścieżki (do PathInfo.Reason).
	reason func(string)

	probeEvery time.Duration // pierwszy odstęp sondy
	probeMax   time.Duration // górna granica odstępu po kolejnych nieudanych powrotach
	stableFor  time.Duration // jak długo szybka ścieżka musi działać, żeby uznać powrót za udany
	retryWait  time.Duration // przerwa, gdy wszystkie ścieżki zawiodły

	curEvery   time.Duration
	upgradedAt time.Time
}

func newPathLoop() *pathLoop {
	return &pathLoop{
		goProbe:    func(f func()) { go f() },
		sleep:      sleepCtx,
		now:        time.Now,
		reason:     func(string) {},
		probeEvery: 5 * time.Second,
		probeMax:   60 * time.Second,
		stableFor:  30 * time.Second,
		retryWait:  2 * time.Second,
	}
}

// loop działa do końca ctx.
func (l *pathLoop) loop(ctx context.Context) {
	for ctx.Err() == nil {
		cfg := l.config()
		gen := l.gen()
		paths := []string{cfg.Path}
		if cfg.Path == PathAuto {
			paths = []string{PathGPU, PathCPU, PathGDI}
		}
		var err error
		for _, p := range paths {
			start := l.now()
			if p == PathGDI && cfg.Path == PathAuto {
				err = l.runDegraded(ctx, cfg, p, gen)
			} else {
				err = l.run(ctx, cfg, p, gen)
				// Szybka ścieżka, która przepracowała dość długo, kasuje karę za wcześniejsze nieudane powroty.
				if p != PathGDI && l.now().Sub(start) >= l.stableFor {
					l.curEvery = 0
				}
			}
			if ctx.Err() != nil || errors.Is(err, errRestart) || errors.Is(err, errUpgrade) {
				break
			}
			if err != nil {
				l.log.Warn("ścieżka silnika zawiodła, próbuję następnej", "path", p, "err", err)
				if p != PathGDI {
					l.reason(err.Error())
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRestart) {
			continue
		}
		if errors.Is(err, errUpgrade) {
			l.upgradedAt = l.now()
			l.log.Info("szybka ścieżka przechwytywania znów działa, wracam z trybu awaryjnego")
			continue
		}
		if !l.sleep(ctx, l.retryWait) {
			return
		}
	}
}

// runDegraded uruchamia ścieżkę awaryjną (GDI) razem z sondą w tle: gdy DXGI znów da się otworzyć, sonda przerywa GDI
// sygnałem errUpgrade, a pętla zaczyna od szybkich ścieżek. Połączenie z widzem zostaje (zmienia się tylko silnik).
func (l *pathLoop) runDegraded(ctx context.Context, cfg Config, path string, gen int64) error {
	if l.curEvery == 0 {
		l.curEvery = l.probeEvery
	} else if !l.upgradedAt.IsZero() && l.now().Sub(l.upgradedAt) < l.stableFor {
		// Wróciliśmy na szybką ścieżkę i od razu z niej spadliśmy: nie sondujemy co 5 s w kółko.
		l.curEvery = min(l.curEvery*2, l.probeMax)
	}
	every := l.curEvery
	gctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	done := make(chan struct{})
	l.goProbe(func() {
		defer close(done)
		for l.sleep(gctx, every) {
			err := l.probe()
			if err == nil {
				cancel(errUpgrade)
				return
			}
			l.log.Debug("sonda DXGI: nadal niedostępne", "err", err)
		}
	})
	err := l.run(gctx, cfg, path, gen)
	cause := context.Cause(gctx)
	cancel(nil)
	<-done
	if errors.Is(cause, errUpgrade) && ctx.Err() == nil {
		return errUpgrade
	}
	return err
}
