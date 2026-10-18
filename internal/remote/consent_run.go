package remote

import (
	"context"
	"errors"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
)

// ErrConsentClosed: podproces okna zgody zakończył się bez odpowiedzi (padł, został zabity). To nie jest odmowa użytkownika, więc
// wołający odpowiada „niedostępne”, a nie „odmówił”.
var ErrConsentClosed = errors.New("okno zgody zakończyło się bez odpowiedzi")

// askConsentWith pokazuje okno zgody przez podproces uruchomiony przez launch (desktop-helper consent z tokenem o wysokiej integralności
// w sesji użytkownika) i czeka na jego decyzję. Brak odpowiedzi w req.Timeout zabija podproces (okno znika) i jest odmową; koniec ctx
// (koniec sesji) też zabija podproces. Decyzję przyjmujemy wyłącznie z potoku podprocesu, który sami uruchomiliśmy: nic z zewnątrz, w tym
// pomocnik, nie ma jak jej podstawić.
func askConsentWith(ctx context.Context, req ConsentRequest, launch func(title, text string) (Process, error)) (ConsentDecision, error) {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = ConsentTimeout
	}
	proc, err := launch(consentTitle, consentText(ConsentRequest{Engineer: req.Engineer, Login: req.Login, Tenant: req.Tenant, Timeout: timeout}))
	if err != nil {
		return ConsentDenied, err
	}
	defer proc.Kill()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case m, ok := <-proc.Messages():
			if !ok {
				return ConsentDenied, ErrConsentClosed
			}
			if m.Kind != ipc.DesktopConsent {
				continue
			}
			if m.State == ipc.ConsentAllow {
				return ConsentAllowed, nil
			}
			return ConsentDenied, nil
		case <-timer.C:
			return ConsentTimedOut, nil
		case <-ctx.Done():
			return ConsentDenied, ctx.Err()
		}
	}
}
