package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var fastRetry = retryPolicy{Attempts: 5, Interval: time.Millisecond}

// accessDenied udaje E_ACCESSDENIED z DuplicateOutput.
var accessDenied = errors.New("DuplicateOutput: HRESULT 0x80070005")

func TestRetryOpenSucceedsAfterTransientAccessDenied(t *testing.T) {
	calls, attaches := 0, 0
	v, err := retryOpen(context.Background(), fastRetry, quiet(), "duplikacja",
		func() (string, error) { attaches++; return "Default", nil },
		func() (int, error) {
			calls++
			if calls <= 3 { // trzy odmowy, czwarta próba przechodzi
				return 0, accessDenied
			}
			return 42, nil
		},
		func(error) bool { return true }, nil)
	if err != nil || v != 42 {
		t.Fatalf("wynik %d, błąd %v", v, err)
	}
	if calls != 4 {
		t.Fatalf("prób: %d, oczekiwano 4", calls)
	}
	if attaches != 4 {
		t.Fatalf("dołączeń do pulpitu: %d, ma być przed każdą próbą (4)", attaches)
	}
}

func TestRetryOpenGivesUpAfterAllAttemptsWithHRESULTAndDesktopInError(t *testing.T) {
	calls := 0
	_, err := retryOpen(context.Background(), fastRetry, quiet(), "duplikacja",
		func() (string, error) { return "Winlogon", nil },
		func() (int, error) { calls++; return 0, accessDenied },
		func(error) bool { return true }, nil)
	if err == nil {
		t.Fatal("po wyczerpaniu prób oczekiwano błędu")
	}
	if calls != 5 {
		t.Fatalf("prób: %d, oczekiwano 5", calls)
	}
	// Błąd niesie dokładny HRESULT i nazwę pulpitu wejściowego (do diagnozy z logu agenta).
	for _, want := range []string{"0x80070005", `"Winlogon"`, "duplikacja"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("błąd %q nie zawiera %q", err, want)
		}
	}
	if !errors.Is(err, accessDenied) {
		t.Fatal("błąd musi zachować przyczynę (errors.Is)")
	}
}

func TestRetryOpenDoesNotRetryPermanentErrors(t *testing.T) {
	calls := 0
	permanent := errors.New("DXGI_ERROR_UNSUPPORTED")
	_, err := retryOpen(context.Background(), fastRetry, quiet(), "duplikacja", nil,
		func() (int, error) { calls++; return 0, permanent },
		func(e error) bool { return !errors.Is(e, permanent) }, nil)
	if err == nil || calls != 1 {
		t.Fatalf("błąd %v, prób %d (oczekiwano 1 próby)", err, calls)
	}
}

func TestRetryOpenAttachFailureDoesNotBlockOpen(t *testing.T) {
	// Dołączenie do pulpitu bywa niemożliwe (brak praw), a otwarcie i tak może się udać na bieżącym pulpicie.
	v, err := retryOpen(context.Background(), fastRetry, quiet(), "x",
		func() (string, error) { return "", errors.New("SetThreadDesktop: odmowa") },
		func() (int, error) { return 7, nil }, nil, nil)
	if err != nil || v != 7 {
		t.Fatalf("wynik %d, błąd %v", v, err)
	}
}

func TestRetryOpenStopsOnRestartRequestAndContext(t *testing.T) {
	calls := 0
	_, err := retryOpen(context.Background(), fastRetry, quiet(), "x", nil,
		func() (int, error) { calls++; return 0, accessDenied },
		nil, func() bool { return calls >= 2 })
	if !errors.Is(err, errRestart) {
		t.Fatalf("błąd %v, oczekiwano errRestart", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := retryOpen(ctx, fastRetry, quiet(), "x", nil, func() (int, error) { return 1, nil }, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("błąd %v, oczekiwano Canceled", err)
	}
}

func TestOpenRetryDefaultsMatchRequirement(t *testing.T) {
	// Wymaganie z testu na prawdziwym komputerze: ok. 5 prób co 300–500 ms.
	if openRetry.Attempts < 5 || openRetry.Interval < 300*time.Millisecond || openRetry.Interval > 500*time.Millisecond {
		t.Fatalf("domyślne ponawianie: %+v", openRetry)
	}
}

func TestRetryOpenExplainsUnavailableInputDesktop(t *testing.T) {
	// OpenInputDesktop odmówił (pulpit zabezpieczony): nazwa pusta, a komunikat mówi wprost, co to znaczy.
	_, err := retryOpen(context.Background(), retryPolicy{Attempts: 2, Interval: time.Millisecond}, quiet(), "duplikacja",
		func() (string, error) { return "", errors.New("OpenInputDesktop: Access is denied.") },
		func() (int, error) { return 0, accessDenied }, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "niedostępny") || !strings.Contains(err.Error(), "0x80070005") {
		t.Fatalf("błąd: %v", err)
	}
}
