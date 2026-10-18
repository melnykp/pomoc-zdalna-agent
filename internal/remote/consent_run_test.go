package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
)

// askConsentWith czyta decyzję wyłącznie z potoku podprocesu okna zgody, który sam uruchomił: zgoda, odmowa, zamknięcie bez odpowiedzi,
// brak odpowiedzi w czasie (podproces zabity, okno znika) i koniec sesji.
func TestAskConsentWithReadsDecisionFromTheConsentProcessOnly(t *testing.T) {
	req := ConsentRequest{SessionID: "s1", Engineer: "Jan\nKowalski", Timeout: 2 * time.Second}
	launcher := func(p *fakeProc, gotTitle, gotText *string) func(title, text string) (Process, error) {
		return func(title, text string) (Process, error) {
			if gotTitle != nil {
				*gotTitle, *gotText = title, text
			}
			return p, nil
		}
	}

	t.Run("zgoda", func(t *testing.T) {
		p := newFakeProc()
		var title, text string
		p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopLog, Text: "inna wiadomość jest pomijana"}
		p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopConsent, State: ipc.ConsentAllow}
		d, err := askConsentWith(context.Background(), req, launcher(p, &title, &text))
		if err != nil || d != ConsentAllowed {
			t.Fatalf("%v %v", d, err)
		}
		if !p.wasKilled() {
			t.Fatal("podproces okna zgody ma zostać zakończony po odpowiedzi")
		}
		if title != consentTitle || !strings.Contains(text, "Inżynier: Jan Kowalski") {
			t.Fatalf("okno dostaje tytuł %q i treść z nazwą inżyniera w osobnej linii z etykietą: %q", title, text)
		}
	})
	t.Run("odmowa", func(t *testing.T) {
		p := newFakeProc()
		p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopConsent, State: ipc.ConsentDeny}
		if d, err := askConsentWith(context.Background(), req, launcher(p, nil, nil)); err != nil || d != ConsentDenied {
			t.Fatalf("%v %v", d, err)
		}
	})
	t.Run("nieznany stan to odmowa", func(t *testing.T) {
		p := newFakeProc()
		p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopConsent, State: "tak"}
		if d, _ := askConsentWith(context.Background(), req, launcher(p, nil, nil)); d != ConsentDenied {
			t.Fatalf("tylko dokładne „allow” zezwala: %v", d)
		}
	})
	t.Run("podproces padł bez odpowiedzi", func(t *testing.T) {
		p := newFakeProc()
		p.close()
		d, err := askConsentWith(context.Background(), req, launcher(p, nil, nil))
		if !errors.Is(err, ErrConsentClosed) || d == ConsentAllowed {
			t.Fatalf("%v %v", d, err)
		}
	})
	t.Run("brak odpowiedzi w czasie", func(t *testing.T) {
		p := newFakeProc()
		short := req
		short.Timeout = 60 * time.Millisecond
		d, err := askConsentWith(context.Background(), short, launcher(p, nil, nil))
		if err != nil || d != ConsentTimedOut {
			t.Fatalf("%v %v", d, err)
		}
		if !p.wasKilled() {
			t.Fatal("po czasie podproces zostaje zabity, a okno znika z ekranu użytkownika")
		}
	})
	t.Run("koniec sesji w trakcie pytania", func(t *testing.T) {
		p := newFakeProc()
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		d, err := askConsentWith(ctx, req, launcher(p, nil, nil))
		if !errors.Is(err, context.Canceled) || d == ConsentAllowed || !p.wasKilled() {
			t.Fatalf("%v %v zabity=%v", d, err, p.wasKilled())
		}
	})
	t.Run("błąd uruchomienia", func(t *testing.T) {
		boom := errors.New("CreateProcessAsUser: odmowa")
		d, err := askConsentWith(context.Background(), req, func(string, string) (Process, error) { return nil, boom })
		if !errors.Is(err, boom) || d == ConsentAllowed {
			t.Fatalf("%v %v", d, err)
		}
	})
}
