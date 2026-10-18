package remote

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// ErrNoGrant: nie ma zgody czekającej na potwierdzenie serwera dla tej sesji (wygasła, została anulowana albo sesja się skończyła).
var ErrNoGrant = errors.New("remote: brak zgody czekającej na potwierdzenie")

// Elevate (Elevator) pyta użytkownika na komputerze o zgodę na podniesienie uprawnień pomocnika na czas bieżącej sesji.
//
//  1. Sprawdza, że sesja jest bieżąca, stały poziom komputera to „user”, UAC jest włączony i nie przekroczono limitów okien zgody.
//  2. WSTRZYMUJE wejście od widza w pomocniku na czas pytania (inżynier nie kliknie w nic obok okna zgody).
//  3. Pokazuje okno zgody (e.Consent): inżynier w osobnych, podpisanych liniach; brak odpowiedzi w ConsentTimeout to odmowa.
//  4. Po zgodzie NIE podnosi jeszcze niczego: zapamiętuje zgodę jako oczekującą na potwierdzenie serwera (pendingGrant) i zwraca ElevationGranted.
//     Poziom podnosi dopiero ActivateElevation (serwer zapisał zgodę w audycie i potwierdził), a CancelElevation (brak potwierdzenia, zerwane
//     połączenie) wznawia wejście i nic nie podnosi. Dzięki temu audyt nigdy nie mówi „odmowa/brak odpowiedzi” przy faktycznie podniesionym pomocniku.
//
// Zgoda dotyczy wyłącznie tej sesji: EndSession (koniec sesji w Managerze) kasuje ją, a nowa sesja pyta od nowa. Zawsze „integrity”, nigdy „admin”.
func (e *Engine) Elevate(ctx context.Context, req ElevationRequest) (ElevationOutcome, error) {
	sessionID := req.SessionID
	if !e.elevMu.TryLock() {
		return outcome(wire.ElevationError, "trwa już prośba o podniesienie uprawnień"), nil
	}
	defer e.elevMu.Unlock()

	e.mu.Lock()
	st := e.cur
	level := e.HelperLevel
	if level == "" {
		level = config.DesktopHelperUser
	}
	already := e.elevatedSession == sessionID
	pending := e.pendingGrant != ""
	lastKind, lastFallback := e.lastChoice.Kind, e.lastChoice.Fallback
	active := st != nil && st.sessionID == sessionID && !st.ended
	uacOff := e.uacOffLocked()
	e.mu.Unlock()

	switch {
	case !active:
		return outcome(wire.ElevationError, "sesja pulpitu nie jest połączona z pomocnikiem"), nil
	case level != config.DesktopHelperUser:
		return outcome(wire.ElevationAlready, "pomocnik ma stały podwyższony poziom ustawiony dla tego komputera"), nil
	case pending:
		return outcome(wire.ElevationError, "poprzednia zgoda czeka jeszcze na potwierdzenie serwera"), nil
	case already && lastKind == TokenIntegrity && !lastFallback:
		return outcome(wire.ElevationAlready, "uprawnienia zostały już podniesione w tej sesji"), nil
	case already:
		return outcome(wire.ElevationError, "zgoda na tę sesję już udzielona, ale pomocnik nie dostał podwyższonych uprawnień (szczegóły w dzienniku agenta)"), nil
	case uacOff:
		return outcome(wire.ElevationUnavailable, "UAC jest wyłączony na tym komputerze: okna administratora nie mają osobnej integralności, więc prośba o zgodę nie ma tu zastosowania"), nil
	}
	if e.CanElevate != nil && !e.CanElevate() {
		return outcome(wire.ElevationUnavailable, "agent nie działa jako usługa, więc nie ma jak zapytać użytkownika o zgodę"), nil
	}
	if e.Consent == nil {
		return outcome(wire.ElevationUnavailable, "ten agent nie umie zapytać użytkownika o zgodę"), nil
	}

	// Limity okien zgody: w sesji, w ostatniej godzinie (niezależnie od sesji) i odstęp od poprzedniego okna.
	e.mu.Lock()
	now := time.Now()
	kept := e.elevHist[:0]
	for _, t := range e.elevHist {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	e.elevHist = kept
	var limited string
	switch {
	case e.elevPrompts >= maxElevationPrompts:
		limited = "w tej sesji pokazano już najwięcej dozwolonych okien zgody"
	case len(e.elevHist) >= maxElevationPromptsPerHour:
		limited = fmt.Sprintf("w ciągu ostatniej godziny pokazano już %d okien zgody", len(e.elevHist))
	case !e.lastPromptEnd.IsZero() && now.Sub(e.lastPromptEnd) < e.promptGap():
		limited = "poprzednie okno zgody zniknęło przed chwilą: poczekaj, zanim poprosisz ponownie"
	}
	if limited == "" {
		e.elevPrompts++
		e.elevHist = append(e.elevHist, now)
	}
	e.mu.Unlock()
	if limited != "" {
		e.Log.Warn("prośba o podniesienie uprawnień pominięta: limit okien zgody", "session_id", sessionID, "powód", limited)
		return outcome(wire.ElevationError, limited), nil
	}

	e.Log.Info("prośba o podniesienie uprawnień pomocnika: pytam użytkownika o zgodę", "session_id", sessionID, "request_id", req.RequestID)
	e.pauseInput(st, true)
	decision, err := e.Consent(ctx, ConsentRequest{SessionID: sessionID, Engineer: req.Engineer, Login: req.Login, Tenant: req.Tenant, Timeout: ConsentTimeout})
	e.mu.Lock()
	e.lastPromptEnd = time.Now()
	e.mu.Unlock()
	resume := func() { e.pauseInput(st, false) }
	switch {
	case ctx.Err() != nil:
		return outcome(wire.ElevationError, "sesja zakończona w trakcie pytania o zgodę"), nil
	case errors.Is(err, ErrNoUserSession):
		resume()
		return outcome(wire.ElevationUnavailable, "nikt nie jest zalogowany na konsoli komputera"), nil
	case err != nil:
		resume()
		e.Log.Warn("okno zgody na podniesienie uprawnień nie zadziałało", "err", err)
		return outcome(wire.ElevationUnavailable, "nie udało się pokazać okna zgody na komputerze: "+err.Error()), nil
	}
	switch decision {
	case ConsentTimedOut:
		resume()
		e.Log.Warn("podniesienie uprawnień pomocnika: brak odpowiedzi użytkownika, odmowa", "session_id", sessionID)
		return outcome(wire.ElevationTimeout, fmt.Sprintf("brak odpowiedzi użytkownika w ciągu %d s (potraktowano jako odmowę)", int(ConsentTimeout/time.Second))), nil
	case ConsentAllowed:
	default:
		resume()
		e.Log.Info("podniesienie uprawnień pomocnika: użytkownik odmówił", "session_id", sessionID)
		return outcome(wire.ElevationDenied, "użytkownik na komputerze odmówił"), nil
	}

	// Zgoda: sesja musi być nadal ta sama (inżynier mógł ją zamknąć w trakcie pytania). Poziomu jeszcze nie podnosimy: czekamy na potwierdzenie
	// serwera (ActivateElevation); wejście zostaje wstrzymane. Bez potwierdzenia w grantTTL zgoda sama się anuluje.
	e.mu.Lock()
	if e.cur != st || ctx.Err() != nil {
		e.mu.Unlock()
		return outcome(wire.ElevationError, "sesja zakończona w trakcie pytania o zgodę"), nil
	}
	e.pendingGrant = sessionID
	e.grantDone = make(chan struct{})
	ttl := e.GrantTTL
	if ttl <= 0 {
		ttl = defaultGrantTTL
	}
	e.grantTimer = time.AfterFunc(ttl, func() { e.CancelElevation(sessionID) })
	e.mu.Unlock()
	e.Log.Info("podniesienie uprawnień pomocnika: użytkownik zezwolił, czekam na potwierdzenie serwera", "session_id", sessionID)
	return outcome(wire.ElevationGranted, "użytkownik zezwolił; pomocnik uruchomi się ponownie z podwyższoną integralnością do końca sesji"), nil
}

// ActivateElevation (ElevationFinisher) wykonuje zgodę po potwierdzeniu serwera: zapamiętuje, że TA sesja ma poziom integrity, zatrzymuje
// działającego pomocnika (z puszczeniem klawiszy) i trzyma sesję „połączoną” przez ReconnectWindow, żeby widz zdążył połączyć się z nowym
// pomocnikiem (nowa oferta dla tej samej sesji uruchomi go już na poziomie integrity).
func (e *Engine) ActivateElevation(sessionID string) error {
	window := e.ReconnectWindow
	if window <= 0 {
		window = defaultReconnectWindow
	}
	e.mu.Lock()
	if e.pendingGrant != sessionID {
		e.mu.Unlock()
		return ErrNoGrant
	}
	st := e.cur
	e.clearGrantLocked()
	if st == nil || st.sessionID != sessionID {
		e.mu.Unlock()
		return ErrNoSession
	}
	e.elevatedSession = sessionID
	e.holdSession, e.holdUntil = sessionID, time.Now().Add(window)
	e.mu.Unlock()
	e.Log.Info("podniesienie uprawnień pomocnika: potwierdzone przez serwer, restart pomocnika na poziomie integrity do końca sesji", "session_id", sessionID)
	e.endState(st)
	return nil
}

// CancelElevation (ElevationFinisher) anuluje zgodę oczekującą na potwierdzenie serwera (brak potwierdzenia, zerwane połączenie, serwer odrzucił
// zgodę): niczego nie podnosi, a wejście od widza wraca.
func (e *Engine) CancelElevation(sessionID string) {
	e.mu.Lock()
	if e.pendingGrant != sessionID {
		e.mu.Unlock()
		return
	}
	st := e.cur
	e.clearGrantLocked()
	e.mu.Unlock()
	e.Log.Warn("podniesienie uprawnień pomocnika anulowane: brak potwierdzenia serwera, poziom bez zmian", "session_id", sessionID)
	if st != nil && st.sessionID == sessionID {
		e.pauseInput(st, false)
	}
}

// promptGap zwraca minimalny odstęp między oknami zgody.
func (e *Engine) promptGap() time.Duration {
	switch {
	case e.PromptGap < 0:
		return 0 // wyłączony (testy)
	case e.PromptGap > 0:
		return e.PromptGap
	}
	return elevationPromptGap
}

// clearGrantLocked zdejmuje zgodę oczekującą na potwierdzenie i budzi oferty czekające na jej rozstrzygnięcie. Wymaga trzymanego e.mu.
func (e *Engine) clearGrantLocked() {
	e.pendingGrant = ""
	if e.grantTimer != nil {
		e.grantTimer.Stop()
		e.grantTimer = nil
	}
	if e.grantDone != nil {
		close(e.grantDone)
		e.grantDone = nil
	}
}

// waitGrant czeka, aż zgoda oczekująca na potwierdzenie serwera dla tej sesji zostanie rozstrzygnięta (aktywowana albo anulowana), żeby oferta
// widza wysłana tuż po zgodzie nie wystartowała pomocnika na starym poziomie.
func (e *Engine) waitGrant(ctx context.Context, sessionID string) {
	e.mu.Lock()
	ch := e.grantDone
	pend := e.pendingGrant == sessionID
	e.mu.Unlock()
	if !pend || ch == nil {
		return
	}
	ttl := e.GrantTTL
	if ttl <= 0 {
		ttl = defaultGrantTTL
	}
	select {
	case <-ch:
	case <-ctx.Done():
	case <-time.After(ttl + 2*time.Second):
	}
}

// pauseInput wstrzymuje albo wznawia wejście od widza w pomocniku danej sesji (pytanie o zgodę trwa).
func (e *Engine) pauseInput(st *helperState, on bool) {
	if st == nil {
		return
	}
	e.mu.Lock()
	proc := st.proc
	e.mu.Unlock()
	if proc == nil {
		return
	}
	kind := ipc.DesktopPause
	if !on {
		kind = ipc.DesktopResume
	}
	_ = proc.Send(ipc.DesktopMsg{Kind: kind, SessionID: st.sessionID})
}
