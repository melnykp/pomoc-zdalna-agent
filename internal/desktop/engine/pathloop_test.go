package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRun to atrapa przechwytywania: każda ścieżka ma skrypt zachowań, a log zapisuje kolejność uruchomień.
type fakeRun struct {
	mu       sync.Mutex
	log      []string
	failFast atomic.Int32 // ile jeszcze razy szybkie ścieżki (gpu, cpu) mają zawieść E_ACCESSDENIED
	// onFast woła się, gdy szybka ścieżka „działa”: blokuje do końca ctx (jak prawdziwa pętla).
	onGDI func(ctx context.Context)
}

func (f *fakeRun) run(ctx context.Context, cfg Config, path string, gen int64) error {
	f.mu.Lock()
	f.log = append(f.log, path)
	f.mu.Unlock()
	switch path {
	case PathGPU, PathCPU:
		if f.failFast.Load() > 0 {
			if path == PathCPU {
				f.failFast.Add(-1)
			}
			return fmt.Errorf("duplikacja: %w", accessDenied)
		}
		<-ctx.Done()
		return nil
	case PathGDI:
		if f.onGDI != nil {
			f.onGDI(ctx)
		} else {
			<-ctx.Done()
		}
		return nil
	}
	return errors.New("nieznana ścieżka")
}

func (f *fakeRun) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func newTestLoop(f *fakeRun, probe func() error) (*pathLoop, *[]time.Duration) {
	var sleeps []time.Duration
	var smu sync.Mutex
	l := newPathLoop()
	l.log = quiet()
	l.config = func() Config { return Config{Path: PathAuto}.normalized() }
	l.gen = func() int64 { return 0 }
	l.run = f.run
	l.probe = probe
	l.probeEvery = time.Millisecond
	l.probeMax = 8 * time.Millisecond
	l.stableFor = time.Hour // w tym teście szybka ścieżka nigdy nie „okrzepnie”, chyba że test ustawi inaczej
	l.retryWait = time.Millisecond
	l.sleep = func(ctx context.Context, d time.Duration) bool {
		smu.Lock()
		sleeps = append(sleeps, d)
		smu.Unlock()
		return sleepCtx(ctx, d)
	}
	return l, &sleeps
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("nie doczekano: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestDegradedGDIReturnsToFastPathWhenDXGIWorksAgain(t *testing.T) {
	f := &fakeRun{}
	f.failFast.Store(1) // pierwszy przebieg gpu+cpu: odmowa; po powrocie szybka ścieżka działa
	var probes atomic.Int32
	probe := func() error {
		// Symulowany E_ACCESSDENIED przez 3 próby, potem sukces.
		if probes.Add(1) <= 3 {
			return accessDenied
		}
		return nil
	}
	l, _ := newTestLoop(f, probe)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()

	// Najpierw gpu, cpu (obie zawodzą), gdi; po 4. sondzie GDI zostaje przerwane i wracamy na gpu, które działa.
	waitUntil(t, "powrót na szybką ścieżkę", func() bool {
		p := f.paths()
		return len(p) >= 4 && p[len(p)-1] == PathGPU
	})
	cancel()
	<-done
	got := f.paths()
	want := []string{PathGPU, PathCPU, PathGDI, PathGPU}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("kolejność ścieżek %v, oczekiwano początku %v", got, want)
		}
	}
	if probes.Load() != 4 {
		t.Fatalf("sond: %d, oczekiwano 4 (3 odmowy + sukces)", probes.Load())
	}
}

func TestNoProbeWhenFastPathWorksOrPathForced(t *testing.T) {
	// Szybka ścieżka działa od początku: sonda w ogóle nie rusza.
	f := &fakeRun{}
	var probes atomic.Int32
	l, _ := newTestLoop(f, func() error { probes.Add(1); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()
	waitUntil(t, "start gpu", func() bool { return len(f.paths()) == 1 })
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if probes.Load() != 0 {
		t.Fatalf("sonda uruchomiona %d razy przy działającej szybkiej ścieżce", probes.Load())
	}

	// Ścieżka GDI wybrana wprost w konfiguracji: bez sondy i bez automatycznych zmian.
	f2 := &fakeRun{}
	l2, _ := newTestLoop(f2, func() error { probes.Add(1); return nil })
	l2.config = func() Config { return Config{Path: PathGDI}.normalized() }
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { l2.loop(ctx2); close(done2) }()
	waitUntil(t, "start gdi", func() bool { return len(f2.paths()) == 1 })
	time.Sleep(20 * time.Millisecond)
	cancel2()
	<-done2
	if probes.Load() != 0 || f2.paths()[0] != PathGDI {
		t.Fatalf("sond %d, ścieżki %v", probes.Load(), f2.paths())
	}
}

func TestProbeBackoffGrowsWhenFastPathKeepsFailingAfterReturn(t *testing.T) {
	// Sonda mówi „działa”, ale szybkie ścieżki nadal padają: bez wydłużania odstępu spadalibyśmy co sondę w kółko.
	f := &fakeRun{}
	f.failFast.Store(1 << 20)
	var probes atomic.Int32
	probe := func() error {
		if probes.Add(1) >= 6 {
			f.failFast.Store(0) // po 6. sondzie DXGI naprawdę działa
		}
		return nil
	}
	l, sleeps := newTestLoop(f, probe)
	now := time.Unix(1000, 0)
	var nmu sync.Mutex
	l.now = func() time.Time { nmu.Lock(); defer nmu.Unlock(); return now }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()
	waitUntil(t, "powrót po wielu próbach", func() bool {
		p := f.paths()
		return len(p) > 0 && p[len(p)-1] == PathGPU && probes.Load() >= 6
	})
	cancel()
	<-done

	// Odstępy sondy: 1 ms, potem podwajane do limitu 8 ms (zegar stoi, więc każdy powrót liczy się jako „zaraz po powrocie”).
	var probeSleeps []time.Duration
	for _, d := range *sleeps {
		if d != l.retryWait {
			probeSleeps = append(probeSleeps, d)
		}
	}
	if len(probeSleeps) < 5 {
		t.Fatalf("za mało odstępów sondy: %v", probeSleeps)
	}
	grew := false
	for i := 1; i < len(probeSleeps); i++ {
		if probeSleeps[i] > probeSleeps[i-1] {
			grew = true
		}
		if probeSleeps[i] > l.probeMax {
			t.Fatalf("odstęp %v przekracza limit %v", probeSleeps[i], l.probeMax)
		}
	}
	if !grew || probeSleeps[len(probeSleeps)-1] != l.probeMax {
		t.Fatalf("odstępy sondy powinny rosnąć do limitu: %v", probeSleeps)
	}
}

func TestStableFastPathResetsProbeBackoff(t *testing.T) {
	f := &fakeRun{}
	f.failFast.Store(1)
	l, _ := newTestLoop(f, func() error { return nil })
	l.stableFor = 10 * time.Second
	clock := time.Unix(1000, 0)
	var nmu sync.Mutex
	l.now = func() time.Time { nmu.Lock(); defer nmu.Unlock(); return clock }
	l.curEvery = 4 * time.Millisecond // pozostałość po wcześniejszych nieudanych powrotach
	f.onGDI = nil
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()
	waitUntil(t, "szybka ścieżka po powrocie", func() bool {
		p := f.paths()
		return len(p) >= 4 && p[len(p)-1] == PathGPU
	})
	// Szybka ścieżka pracuje „długo” (zegar skacze), po jej końcu kara ma zniknąć.
	nmu.Lock()
	clock = clock.Add(time.Minute)
	nmu.Unlock()
	cancel()
	<-done
	if l.curEvery != 0 {
		t.Fatalf("po stabilnej pracy szybkiej ścieżki odstęp sondy powinien wrócić do bazowego (0), a jest %v", l.curEvery)
	}
}

func TestRestartRequestOnDegradedPathStartsNewRoundFromFastPaths(t *testing.T) {
	f := &fakeRun{}
	f.failFast.Store(1 << 20)
	l, _ := newTestLoop(f, func() error { return accessDenied })
	var gdiRuns atomic.Int32
	inner := l.run
	l.run = func(ctx context.Context, cfg Config, path string, g int64) error {
		if path == PathGDI && gdiRuns.Add(1) == 1 {
			return errRestart // widz zmienił monitor w trakcie pracy awaryjnej
		}
		return inner(ctx, cfg, path, g)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()
	waitUntil(t, "druga runda od szybkich ścieżek", func() bool { return len(f.paths()) >= 5 })
	cancel()
	<-done
	// Pierwsze uruchomienie GDI kończy się sygnałem restartu bez wejścia w atrapę, więc nie ma go w dzienniku.
	want := []string{PathGPU, PathCPU, PathGPU, PathCPU, PathGDI}
	got := f.paths()
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("kolejność %v, oczekiwano początku %v", got, want)
		}
	}
}

func TestReasonIsRecordedForFastPathFailures(t *testing.T) {
	f := &fakeRun{}
	f.failFast.Store(1 << 20)
	var reasons []string
	var rmu sync.Mutex
	l, _ := newTestLoop(f, func() error { return accessDenied })
	l.reason = func(s string) { rmu.Lock(); reasons = append(reasons, s); rmu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.loop(ctx); close(done) }()
	waitUntil(t, "powód zejścia", func() bool { rmu.Lock(); defer rmu.Unlock(); return len(reasons) >= 2 })
	cancel()
	<-done
	rmu.Lock()
	defer rmu.Unlock()
	if reasons[0] == "" || reasons[0] != fmt.Sprintf("duplikacja: %v", accessDenied) {
		t.Fatalf("powód: %q", reasons[0])
	}
}
