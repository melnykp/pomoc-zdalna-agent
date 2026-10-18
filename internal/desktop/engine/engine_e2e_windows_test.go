//go:build windows

package engine

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
)

type countingSink struct {
	mu       sync.Mutex
	frames   int
	keys     int
	pointers int
	shapes   int
}

func (s *countingSink) WriteFrame(_ []byte, key bool, _ uint32, _ float64) error {
	s.mu.Lock()
	s.frames++
	if key {
		s.keys++
	}
	s.mu.Unlock()
	return nil
}

func (s *countingSink) Pointer(p capture.Pointer) {
	s.mu.Lock()
	s.pointers++
	if p.Shape != nil {
		s.shapes++
	}
	s.mu.Unlock()
}

func (s *countingSink) snapshot() (frames, keys, pointers, shapes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frames, s.keys, s.pointers, s.shapes
}

// TestForcedGDIPathProducesFramesAndCursorOnThisDesktop uruchamia prawdziwy silnik na ścieżce awaryjnej (GDI): ma oddawać
// klatki H.264, osobno kursor (z kształtem) i zgłosić tryb awaryjny. Przechwytuje ekran tego komputera, więc działa tylko na
// żądanie: RMM_DESKTOP_E2E=1.
func TestForcedGDIPathProducesFramesAndCursorOnThisDesktop(t *testing.T) {
	if os.Getenv("RMM_DESKTOP_E2E") != "1" {
		t.Skip("ustaw RMM_DESKTOP_E2E=1, test przechwytuje ekran tego komputera")
	}
	e := New(Config{Path: PathGDI, FPS: 30}, nil)
	var pmu sync.Mutex
	var infos []PathInfo
	e.SetOnPath(func(p PathInfo) { pmu.Lock(); infos = append(infos, p); pmu.Unlock() })
	sink := &countingSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = e.Run(ctx, sink); close(done) }()
	<-ctx.Done()
	<-done

	frames, keys, pointers, shapes := sink.snapshot()
	t.Logf("GDI przez 4 s: klatek %d (kluczowych %d), komunikatów kursora %d (kształtów %d), ścieżka %+v", frames, keys, pointers, shapes, e.Path())
	if frames < 10 || keys < 1 {
		t.Fatalf("za mało klatek z GDI: %d (kluczowych %d)", frames, keys)
	}
	if pointers < 1 {
		t.Fatal("GDI nie podało kursora")
	}
	pmu.Lock()
	defer pmu.Unlock()
	if len(infos) == 0 || infos[0].Path != PathGDI || !infos[0].Degraded {
		t.Fatalf("tryb awaryjny niezgłoszony: %+v", infos)
	}
}

// TestAutoPathStaysOnFastPathOnThisDesktop sprawdza, że na zdrowym komputerze tryb auto nie schodzi na GDI.
func TestAutoPathStaysOnFastPathOnThisDesktop(t *testing.T) {
	if os.Getenv("RMM_DESKTOP_E2E") != "1" {
		t.Skip("ustaw RMM_DESKTOP_E2E=1, test przechwytuje ekran tego komputera")
	}
	e := New(Config{FPS: 30}, nil)
	sink := &countingSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = e.Run(ctx, sink); close(done) }()
	<-ctx.Done()
	<-done
	frames, _, _, _ := sink.snapshot()
	p := e.Path()
	t.Logf("auto przez 4 s: klatek %d, ścieżka %+v, błąd %q", frames, p, e.Stats().LastError)
	if p.Degraded || p.Path == "" {
		t.Fatalf("auto zeszło na tryb awaryjny: %+v (błąd %q)", p, e.Stats().LastError)
	}
	if frames < 2 { // na nieruchomym ekranie po starcie koder oddaje głównie klatki podtrzymujące
		t.Fatalf("za mało klatek: %d", frames)
	}
}
