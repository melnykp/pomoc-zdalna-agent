//go:build windows

package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
)

// consentViaHelper pokazuje użytkownikowi na konsoli okno zgody na podniesienie uprawnień pomocnika.
//
// Okno rysuje podproces desktop-helper.exe (polecenie consent) uruchomiony przez usługę z tokenem o WYSOKIEJ integralności (poziom „integrity”:
// zwykły token użytkownika, wysoka integralność, bez praw administratora). Dzięki temu UIPI chroni je przed wejściem wstrzykiwanym z
// pomocnika na poziomie „user” (średnia integralność): inżynier nie kliknie „Tak” we własnej prośbie. To bariera użyteczności i zgoda
// użytkownika w obrębie jednego pulpitu, a NIE twarda granica bezpieczeństwa (UIPI nią nie jest, okno można zasłonić innym oknem; osobny pulpit
// zgody to dług na etap 1b). NIE używamy WTSSendMessage: sprawdzone empirycznie, że okno csrss z WTSSendMessage dało się zatwierdzić
// wstrzykniętym kliknięciem z procesu o średniej integralności.
//
// Fail closed: gdy nie da się dostać tokenu o wysokiej integralności (brak SeTcb, zapas na średnią), okna nie pokazujemy, bo mogłoby je
// zatwierdzić wstrzykiwane wejście. Plik pomocnika jest weryfikowany skrótem jak przed każdym startem pomocnika.
func (e *Engine) consentViaHelper(ctx context.Context, req ConsentRequest) (ConsentDecision, error) {
	if e.Verify != nil {
		if err := e.Verify(e.Exe); err != nil {
			return ConsentDenied, err
		}
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF || session == 0 {
		return ConsentDenied, ErrNoUserSession
	}
	var user windows.Token
	if err := windows.WTSQueryUserToken(session, &user); err != nil {
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			return ConsentDenied, ErrNoUserSession
		}
		return ConsentDenied, fmt.Errorf("token użytkownika sesji %d: %w", session, err)
	}
	defer user.Close()
	tok, choice, done, err := chooseHelperToken(user, session, config.DesktopHelperIntegrity, realTokenOps())
	if err != nil {
		return ConsentDenied, fmt.Errorf("token okna zgody: %w", err)
	}
	defer done()
	if choice.Kind != TokenIntegrity {
		return ConsentDenied, fmt.Errorf("okno zgody wymaga tokenu o wysokiej integralności (chronionego przed zdalnym zatwierdzeniem), a jest %s: %s", choice.Kind, choice.Reason)
	}
	return askConsentWith(ctx, req, func(title, text string) (Process, error) {
		b64 := base64.StdEncoding.EncodeToString
		return startWithToken(tok, user, true, session, e.Exe, e.Log, "consent", b64([]byte(title)), b64([]byte(text)))
	})
}
