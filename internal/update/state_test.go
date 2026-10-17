package update

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestAndResultRoundTrip(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	if _, err := p.ReadRequest(); !errors.Is(err, ErrNone) {
		t.Fatalf("brak prośby to ErrNone, jest %v", err)
	}
	req := Request{ReleaseID: "r-1", Component: "agent", Version: "1.3.0", FromVersion: "1.2.0", Path: filepath.Join(p.Staging(), "a.exe"), SHA256: "abc", Size: 10, AuthenticodeSubject: "CN=Firma", RequestedAt: time.Now().UTC().Truncate(time.Second)}
	if err := p.WriteRequest(req); err != nil {
		t.Fatal(err)
	}
	got, err := p.ReadRequest()
	if err != nil || got != req {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if err := p.RemoveRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadRequest(); !errors.Is(err, ErrNone) {
		t.Fatal("po usunięciu prośby nie ma")
	}
	if err := p.RemoveRequest(); err != nil {
		t.Fatalf("usunięcie nieistniejącej prośby nie jest błędem: %v", err)
	}

	res := Result{ReleaseID: "r-1", Version: "1.3.0", FromVersion: "1.2.0", State: StateRolledBack, Error: "nie wstał", At: time.Now().UTC().Truncate(time.Second)}
	if err := p.WriteResult(res); err != nil {
		t.Fatal(err)
	}
	if r, err := p.ReadResult(); err != nil || r != res {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestBadReleasesAreRememberedAndBounded(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	if p.IsBad("x") {
		t.Fatal("nic nie jest oznaczone")
	}
	for _, id := range []string{"a", "b", "a"} {
		if err := p.MarkBad(id); err != nil {
			t.Fatal(err)
		}
	}
	if !p.IsBad("a") || !p.IsBad("b") || p.IsBad("c") {
		t.Fatal("pamięć odrzuconych wydań")
	}
	for i := 0; i < 80; i++ {
		_ = p.MarkBad(string(rune('A'+i%26)) + string(rune('a'+i/26)))
	}
	ids, _ := p.badLocked()
	if len(ids) > maxBad {
		t.Fatalf("lista ma %d wpisów, limit %d", len(ids), maxBad)
	}
}

func TestStartsAreCountedInWindow(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Minute, -9 * time.Minute, -5 * time.Minute, -1 * time.Minute} {
		if err := p.RecordStart(now.Add(d)); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.StartsSince(now.Add(-10 * time.Minute)); n != 3 {
		t.Fatalf("w oknie 10 min są 3 starty, jest %d", n)
	}
	if err := p.ClearStarts(); err != nil {
		t.Fatal(err)
	}
	if n := p.StartsSince(now.Add(-time.Hour)); n != 0 {
		t.Fatalf("po wyczyszczeniu 0 startów, jest %d", n)
	}
}

func TestHealthRoundTrip(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	if _, err := p.ReadHealth(); !errors.Is(err, ErrNone) {
		t.Fatal("brak znacznika to ErrNone")
	}
	h := Health{Version: "1.3.0", Phase: PhaseConnected, PID: 42, At: time.Now().UTC().Truncate(time.Second)}
	if err := p.WriteHealth(h); err != nil {
		t.Fatal(err)
	}
	if got, err := p.ReadHealth(); err != nil || got != h {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if err := p.RemoveHealth(); err != nil {
		t.Fatal(err)
	}
}

func TestIntentionalRestartMarkerIsConsumedOnceAndExpires(t *testing.T) {
	p := Paths{Root: t.TempDir()}
	if p.ConsumeIntentionalRestart(time.Now()) {
		t.Fatal("bez znacznika nie ma zamierzonego restartu")
	}
	if err := p.MarkIntentionalRestart(); err != nil {
		t.Fatal(err)
	}
	if !p.ConsumeIntentionalRestart(time.Now()) {
		t.Fatal("świeży znacznik powinien zostać rozpoznany")
	}
	if p.ConsumeIntentionalRestart(time.Now()) {
		t.Fatal("znacznik można skonsumować tylko raz")
	}
	if err := p.MarkIntentionalRestart(); err != nil {
		t.Fatal(err)
	}
	if p.ConsumeIntentionalRestart(time.Now().Add(10 * time.Minute)) {
		t.Fatal("stary znacznik nie może zwalniać z liczenia awarii")
	}
}
