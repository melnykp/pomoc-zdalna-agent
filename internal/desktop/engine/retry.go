package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Sygnały sterujące pętlą ścieżek (nie są błędami ścieżki).
var (
	// errRestart każe pętli zacząć od nowa z bieżącą konfiguracją (zmiana monitora albo klatek).
	errRestart = errors.New("engine: restart na żądanie")
	// errUpgrade przerywa pracę awaryjną (GDI), bo szybka ścieżka znów działa.
	errUpgrade = errors.New("engine: powrót na szybką ścieżkę")
)

// retryPolicy opisuje ponawianie otwarcia źródła obrazu. Odmowa dostępu przy DuplicateOutput (E_ACCESSDENIED) bywa
// przejściowa: pulpit wejściowy jeszcze się przełącza (odblokowanie, UAC, zmiana użytkownika), więc kilka prób w krótkich
// odstępach zwykle wystarcza, a zejście na GDI przy pierwszej odmowie na kilkanaście minut kosztowało obraz bez okien
// warstwowych i 16 kl./s.
type retryPolicy struct {
	Attempts int
	Interval time.Duration
}

// openRetry to domyślne ponawianie otwarcia DXGI przed zejściem na kolejną ścieżkę (zmienne pakietu, żeby testy mogły skrócić).
var openRetry = retryPolicy{Attempts: 5, Interval: 400 * time.Millisecond}

// sleepCtx czeka d albo do końca ctx; false, gdy ctx się skończył.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// retryOpen próbuje open do pol.Attempts razy. Przed KAŻDĄ próbą woła attach (dołączenie wątku do pulpitu wejściowego;
// zwraca jego nazwę), a każdą porażkę loguje z dokładnym błędem (z HRESULT) i nazwą pulpitu wejściowego. Błędy, dla których
// retryable zwróci false, kończą ponawianie od razu. stop() = true przerywa z errRestart (żądanie zmiany konfiguracji).
func retryOpen[T any](ctx context.Context, pol retryPolicy, log *slog.Logger, what string, attach func() (string, error), open func() (T, error), retryable func(error) bool, stop func() bool) (T, error) {
	var zero T
	if pol.Attempts < 1 {
		pol.Attempts = 1
	}
	var last error
	for i := 1; i <= pol.Attempts; i++ {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		if stop != nil && stop() {
			return zero, errRestart
		}
		desktop := ""
		if attach != nil {
			name, aerr := attach()
			desktop = name
			if aerr != nil {
				log.Debug("dołączenie do pulpitu wejściowego nieudane", "what", what, "attempt", i, "err", aerr)
			}
		}
		v, err := open()
		if err == nil {
			if i > 1 {
				log.Info("źródło obrazu otwarte po ponowieniu", "what", what, "attempt", i, "input_desktop", desktop)
			}
			return v, nil
		}
		shown := desktop
		if shown == "" {
			shown = "niedostępny (OpenInputDesktop odmówił: pulpit zabezpieczony, np. blokada, logowanie albo UAC)"
		}
		last = fmt.Errorf("%w (pulpit wejściowy %q)", err, shown)
		log.Warn("otwarcie źródła obrazu nieudane", "what", what, "attempt", i, "of", pol.Attempts, "input_desktop", shown, "err", err)
		if retryable != nil && !retryable(err) {
			break
		}
		if i < pol.Attempts && !sleepCtx(ctx, pol.Interval) {
			return zero, ctx.Err()
		}
	}
	return zero, fmt.Errorf("%s: %w", what, last)
}
