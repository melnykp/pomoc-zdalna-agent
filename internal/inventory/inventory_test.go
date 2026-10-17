package inventory

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestCollectBasics(t *testing.T) {
	inv, err := Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Family != runtime.GOOS || inv.OS.Hostname == "" || inv.Hardware.CPUCores < 1 {
		t.Fatalf("podstawy: %+v", inv.OS)
	}
	if inv.Disks == nil || inv.Network == nil || inv.Software == nil {
		t.Fatal("listy muszą być puste, a nie nil, bo serwer odrzuca null")
	}
	if time.Since(inv.CollectedAt) > time.Minute {
		t.Fatalf("zły czas zebrania: %v", inv.CollectedAt)
	}
}

func TestCollectHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx); err == nil {
		t.Fatal("anulowany kontekst powinien przerwać zbieranie")
	}
}

// Serwer sprawdza kształt (docs/ARCHITECTURE.md): listy to tablice, a wersje mieszczą się w limitach.
func TestInventoryJSONShapeMatchesServerSchema(t *testing.T) {
	inv, err := Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"disks", "network", "software"} {
		if _, ok := m[k].([]any); !ok {
			t.Errorf("%s powinno być tablicą, jest %T", k, m[k])
		}
	}
	if len(raw) > 2<<20 {
		t.Fatalf("inwentaryzacja ma %d B, limit ramki 2 MB", len(raw))
	}
	for _, s := range inv.Software {
		if s.Name == "" || len(s.Name) > 1024 || len(s.InstalledOn) != 0 && len(s.InstalledOn) != 10 {
			t.Errorf("pozycja poza ograniczeniami serwera: %+v", s)
		}
	}
}
