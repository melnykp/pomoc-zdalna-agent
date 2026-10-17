package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// SelfTestOptions konfiguruje samotest modułu pulpitu na prawdziwym komputerze.
type SelfTestOptions struct {
	Module Module
	// Installer to plik instalacyjny klienta (oficjalny plik RustDesk), potrzebny tylko wtedy, gdy klienta jeszcze nie ma.
	Installer string
	// Wait to jak długo czekać na połączenie inżyniera po otwarciu sesji (domyślnie 2 minuty).
	Wait time.Duration
	// Poll to odstęp odpytywania o stan połączenia (domyślnie 1 s).
	Poll time.Duration
	Out  io.Writer
}

// SelfTest przechodzi ten sam kod co produkcyjne sesje: instalacja klienta (jeśli trzeba), konfiguracja i zamknięcie dostępu,
// odczyt identyfikatora, otwarcie sesji z hasłem jednorazowym, czekanie na połączenie z drugiego komputera i zamknięcie
// dostępu po rozłączeniu. Wypisuje wynik każdego kroku. Wymaga uprawnień administratora (instalacja i ustawienia klienta).
func SelfTest(ctx context.Context, o SelfTestOptions) error {
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	wait, poll := o.Wait, o.Poll
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	if poll <= 0 {
		poll = time.Second
	}
	step := func(ok bool, format string, args ...any) {
		mark := "[OK]    "
		if !ok {
			mark = "[BŁĄD]  "
		}
		fmt.Fprintf(out, "%s%s\n", mark, fmt.Sprintf(format, args...))
	}

	events := make(chan string, 8)
	mgr := NewManager(Options{
		Module: o.Module,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Emit:   func(_, state string) { events <- state },
		Poll:   poll,
	})

	fmt.Fprintln(out, "Samotest modułu pulpitu. Wymaga uprawnień administratora i drugiego komputera z klientem RustDesk skonfigurowanym na nasz serwer.")

	if !o.Module.Installed() {
		if o.Installer == "" {
			step(false, "klient pulpitu nie jest zainstalowany; podaj plik instalacyjny przez --installer")
			return ErrNotInstalled
		}
		fmt.Fprintf(out, "Instaluję klienta z %s (cicha instalacja, do 90 s)...\n", o.Installer)
		if err := mgr.Install(ctx, o.Installer); err != nil {
			step(false, "instalacja klienta: %v", err)
			return err
		}
		step(true, "klient zainstalowany")
	} else {
		step(true, "klient pulpitu jest zainstalowany")
	}
	if v, ok := o.Module.(Versioner); ok {
		step(true, "wersja klienta: %s", v.Version(ctx))
	}
	step(o.Module.Running(ctx), "usługa klienta działa: %v", o.Module.Running(ctx))

	if err := mgr.Prepare(ctx); err != nil {
		step(false, "konfiguracja i hasło zamykające: %v", err)
		if errors.Is(err, ErrNeedsAdmin) {
			fmt.Fprintln(out, "Uruchom polecenie w PowerShellu jako administrator.")
		}
		return err
	}
	step(true, "opcje klienta ustawione (nasz serwer, tylko hasło, bez LAN i bez połączeń po IP), dostęp zamknięty losowym hasłem")

	sess, err := mgr.Open(ctx, "samotest", wait)
	if err != nil {
		step(false, "otwarcie sesji: %v", err)
		return err
	}
	step(true, "sesja otwarta, hasło jednorazowe ustawione")
	fmt.Fprintf(out, "\n  ID:    %s\n  Hasło: %s\n  Link:  rustdesk://connection/new/%s?password=%s\n\n", sess.RemoteID, sess.OTP, sess.RemoteID, sess.OTP)
	fmt.Fprintf(out, "Połącz się z drugiego komputera (RustDesk skonfigurowany na nasz serwer). Czekam do %s...\n", sess.ExpiresAt.Format("15:04:05"))

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	connected := false
	for done := false; !done; {
		select {
		case <-ctx.Done():
			_ = mgr.Close(context.Background(), "samotest")
			step(false, "przerwano: %v", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			mgr.Tick(ctx)
		case ev := <-events:
			switch ev {
			case StateConnected:
				connected = true
				step(true, "wykryto połączenie przychodzące (proces menedżera połączeń)")
				fmt.Fprintln(out, "Rozłącz się, gdy skończysz próbę. Dostęp zostanie zamknięty automatycznie.")
			case StateDisconnected:
				step(true, "rozłączenie wykryte, dostęp zamknięty nowym losowym hasłem")
				done = true
			case StateExpired:
				step(false, "nikt się nie połączył w czasie życia hasła; dostęp zamknięty")
				done = true
			default:
				done = true
			}
		}
	}
	if !connected {
		return errors.New("samotest: brak połączenia w czasie życia hasła")
	}
	fmt.Fprintln(out, "\nWynik: wszystkie kroki przeszły. Moduł pulpitu działa na tym komputerze.")
	return nil
}
