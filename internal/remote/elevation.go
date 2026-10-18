package remote

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Podniesienie uprawnień na żądanie (model ScreenConnect, ADR-0009, wydanie 0.4.3): domyślny pomocnik działa jako zwykły
// użytkownik (średnia integralność). Gdy inżynier w widzu trafi na okno administratora (UIPI), prosi o podniesienie, a użytkownik
// siedzący przy komputerze zezwala w oknie zgody. Po zgodzie (i po potwierdzeniu zapisu w audycie przez serwer) pomocnik jest
// uruchamiany ponownie na poziomie „integrity” TYLKO na czas tej sesji; po jej zakończeniu wraca „user”.
//
// Co to jest, a co nie: to ZGODA UŻYTKOWNIKA i BARIERA UŻYTECZNOŚCI w obrębie jednego pulpitu (okno zgody o wysokiej integralności, wstrzymanie
// wejścia z pomocnika na czas pytania, limity pytań), a NIE twarda granica bezpieczeństwa: UIPI nie jest granicą bezpieczeństwa, a okno zgody
// może zostać zasłonięte innym oknem na tym samym pulpicie. Osobny pulpit zgody to dług na etap 1b (ADR-0009).

const (
	// ConsentTimeout to czas na odpowiedź użytkownika w oknie zgody; brak odpowiedzi to odmowa.
	ConsentTimeout = 60 * time.Second
	// defaultReconnectWindow to czas, w którym sesja pozostaje „połączona” po zgodzie, czekając na ponowne połączenie widza z nowym
	// pomocnikiem (stary został zatrzymany). Po tym czasie Manager uznaje sesję za rozłączoną.
	defaultReconnectWindow = 90 * time.Second
	// defaultGrantTTL to czas, w którym zgoda czeka na potwierdzenie serwera (ack) przed anulowaniem.
	defaultGrantTTL = 30 * time.Second
	// maxElevationPrompts to najwięcej okien zgody pokazanych użytkownikowi w jednej sesji; maxElevationPromptsPerHour liczy okna z ostatniej
	// godziny NIEZALEŻNIE od sesji (koniec sesji tego nie zeruje); elevationPromptGap to minimalny odstęp od końca poprzedniego okna.
	// Limity pilnuje sam agent (serwer też ma swoje), więc przejęty albo błędny serwer nie zaleje użytkownika oknami, a kolejne okno tuż
	// po odmowie nie pojawi się seryjnie.
	maxElevationPrompts        = 3
	maxElevationPromptsPerHour = 6
	elevationPromptGap         = 10 * time.Second
	// maxLabelRunes ogranicza każdą linię z danymi z serwera pokazywaną w oknie zgody.
	maxLabelRunes = 60
)

// ElevationRequest to prośba inżyniera o podniesienie uprawnień pomocnika w trwającej sesji (z serwera).
type ElevationRequest struct {
	SessionID string
	RequestID string
	// Engineer to nazwa wyświetlana, Login e-mail inżyniera, Tenant nazwa firmy (klienta) komputera: pokazywane w oknie zgody w osobnych liniach.
	Engineer string
	Login    string
	Tenant   string
}

// ConsentRequest opisuje pytanie do użytkownika na komputerze.
type ConsentRequest struct {
	SessionID string
	Engineer  string
	Login     string
	Tenant    string
	Timeout   time.Duration
}

// ConsentDecision to odpowiedź użytkownika.
type ConsentDecision int

const (
	// ConsentDenied: użytkownik odmówił.
	ConsentDenied ConsentDecision = iota
	// ConsentAllowed: użytkownik zezwolił.
	ConsentAllowed
	// ConsentTimedOut: brak odpowiedzi w czasie (traktowany jak odmowa).
	ConsentTimedOut
)

// ElevationOutcome to wynik prośby o podniesienie uprawnień dla serwera (wire.Elevation*). Reason jest krótkim opisem dla
// inżyniera i audytu. Dla ElevationGranted podniesienie jest jeszcze NIEWYKONANE: dopiero ActivateElevation po potwierdzeniu serwera.
type ElevationOutcome struct {
	State  string
	Reason string
}

func outcome(state, reason string) ElevationOutcome {
	return ElevationOutcome{State: state, Reason: reason}
}

// Elevator to moduł, który potrafi podnieść uprawnienia pomocnika na czas bieżącej sesji za zgodą użytkownika (własny silnik).
type Elevator interface {
	Elevate(ctx context.Context, req ElevationRequest) (ElevationOutcome, error)
}

// ElevationFinisher domyka zgodę udzieloną w Elevate: po potwierdzeniu serwera ActivateElevation podnosi poziom pomocnika w tej sesji,
// a CancelElevation (brak potwierdzenia, zerwane połączenie, odrzucona zgoda) wznawia wejście i niczego nie podnosi.
type ElevationFinisher interface {
	ActivateElevation(sessionID string) error
	CancelElevation(sessionID string)
}

// plainLabel przygotowuje daną z serwera do pokazania w osobnej, podpisanej linii okna zgody: zostają litery, cyfry, pojedyncze spacje i
// znaki @ . - _ + , &; znaki sterujące, formatujące i separatory linii zamieniają się w spację, a cudzysłowy, nawiasy, dwukropki, znaki
// równości i reszta interpunkcji znikają, więc nie da się udać dalszej części komunikatu („Tak = zezwalam”) ani zamknąć cytatu.
func plainLabel(s string, maxRunes int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || unicode.IsSpace(r):
			space = b.Len() > 0
		case unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || strings.ContainsRune("@.-_+,&", r):
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if rs := []rune(out); len(rs) > maxRunes {
		out = strings.TrimSpace(string(rs[:maxRunes])) + "…"
	}
	return out
}

// consentTitle to tytuł okna zgody.
const consentTitle = "Piotr Melnyk IT - POMOC Zdalna"

// consentText składa treść okna zgody. Dane z serwera są w osobnych liniach z etykietami („Inżynier:”, „Firma:”) i oczyszczone (plainLabel),
// a przyciski okna są systemowe (Tak/Nie, napisy zależą od języka systemu), więc treść mówi wprost, co oznaczają; domyślnie zaznaczone jest „Nie”.
// Okno nie obiecuje twardej ochrony: pyta o zgodę na czas tej sesji.
func consentText(req ConsentRequest) string {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = ConsentTimeout
	}
	name, login := plainLabel(req.Engineer, maxLabelRunes), plainLabel(req.Login, maxLabelRunes*2)
	who := login
	switch {
	case who == "":
		who = name
	case name != "" && name != login:
		who = login + " (" + name + ")"
	}
	if who == "" {
		who = "brak danych"
	}
	lines := "Prośba o podniesienie uprawnień w zdalnej sesji pomocy.\n\nInżynier: " + who + "\n"
	if tenant := plainLabel(req.Tenant, maxLabelRunes); tenant != "" {
		lines += "Firma: " + tenant + "\n"
	}
	return lines + "\nInżynier prosi o możliwość sterowania oknami uruchomionymi jako administrator na czas tej sesji.\n\n" +
		"Czy zezwalasz?\n" +
		"  Tak = zezwalam (tylko na czas tej sesji)\n" +
		"  Nie = odmawiam\n\n" +
		"Brak odpowiedzi w ciągu " + strconv.Itoa(int(timeout/time.Second)) + " sekund oznacza odmowę. Zgoda wygasa wraz z końcem sesji."
}
