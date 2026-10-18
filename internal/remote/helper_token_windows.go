//go:build windows

package remote

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/wintoken"
)

// Typy podniesienia tokenu (TOKEN_ELEVATION_TYPE).
const (
	elevationDefault = 1
	elevationFull    = 2
	elevationLimited = 3
)

// tokenOps to operacje na tokenach potrzebne do wyboru; w produkcji realTokenOps, w testach atrapy (uchwyty to dowolne liczby).
type tokenOps struct {
	elevationType func(t windows.Token) (uint32, error)
	linkedToken   func(t windows.Token) (windows.Token, error)           // TokenLinkedToken: token podniesiony, poziom identyfikacji albo podszywania
	toPrimary     func(t windows.Token) (windows.Token, error)           // DuplicateTokenEx → TokenPrimary (niezależna kopia)
	setSession    func(t windows.Token, session uint32) error            // TokenSessionId (wymaga SeTcbPrivilege)
	restrict      func(t windows.Token, lua bool) (windows.Token, error) // CreateRestrictedToken(DISABLE_MAX_PRIVILEGE[|LUA_TOKEN])
	setIntegrity  func(t windows.Token, rid uint32) error                // TokenIntegrityLevel (podniesienie wymaga SeTcbPrivilege)
	inspect       func(t windows.Token) (wintoken.Info, error)
	closeToken    func(t windows.Token)
}

// chooseHelperToken wybiera token, z którym uruchomimy pomocnika, na podstawie tokenu użytkownika (z WTSQueryUserToken)
// i poziomu z konfiguracji. Usługa działa jako SYSTEM (ma SeTcbPrivilege), ale pomocnik NIGDY nie dostaje konta SYSTEM.
//
// Poziomy:
//   - „integrity” (świadomie włączany dla komputera bez nadzoru albo na czas sesji za zgodą użytkownika): ZWYKŁY (filtrowany) token użytkownika, kopia główna w sesji użytkownika, z odjętymi
//     uprawnieniami i PODNIESIONĄ integralnością do wysokiej, BEZ włączonej grupy Administratorzy. UIPI porównuje wyłącznie poziom
//     integralności, nie członkostwo w grupie, więc taki pomocnik może wstrzykiwać wejście do okien uruchomionych jako administrator,
//     a po przejęciu pomocnika (błąd w kodzie sieciowym) napastnik NIE dostaje praw administratora: nie założy usługi, nie nadpisze
//     plików w Program Files, nie zapisze w HKLM. Działa też na kontach standardowych.
//   - „admin”: połączony token UAC TEGO SAMEGO użytkownika (Limited) albo jego pełny token (Full), w obu wypadkach z odjętymi
//     uprawnieniami. Grupa Administratorzy zostaje włączona, więc to świadomy wybór z większą szkodą po przejęciu pomocnika.
//   - „user” (domyślny, także pusty): token średniej integralności (jak w 0.4.2).
//
// Odjęcie uprawnień (CreateRestrictedToken z DISABLE_MAX_PRIVILEGE) to obrona w głąb, NIE granica bezpieczeństwa: zamyka drogi
// przez SeDebug/SeLoadDriver/SeBackup/SeRestore/SeTakeOwnership, ale nie odbiera dostępu opartego na grupach tokenu. Granicą jest
// brak grupy Administratorzy w poziomie „integrity”.
//
// Każdy zwrócony token jest porównywany z tokenem użytkownika (TokenUser i TokenSessionId muszą się zgadzać), a dla poziomu
// „integrity” sprawdzamy jeszcze, że integralność jest wysoka i grupa Administratorzy NIE jest włączona. Gdy wybrany poziom
// się nie uda, zapas to token średniej integralności; jeśli token użytkownika jest podniesiony (UAC wyłączone, wbudowany
// administrator), zapas i poziom „user” dostają jego odchudzoną wersję (LUA_TOKEN + bez uprawnień + integralność średnia), a gdy
// i tego nie da się zrobić, funkcja zwraca BŁĄD: pomocnik nie startuje, zamiast dostać pełny token.
//
// Zwrócony token należy zamknąć przez done (nie zamyka tokenu użytkownika podanego w user, jest on własnością wołającego).
func chooseHelperToken(user windows.Token, session uint32, level string, ops tokenOps) (tok windows.Token, choice TokenChoice, done func(), err error) {
	noop := func() {}
	if level == "" {
		level = config.DesktopHelperUser
	}
	choice = TokenChoice{Level: level, Elevation: "unknown"}
	// Sesja 0 to sesja usług, nie użytkownika: tam nie ma pulpitu, a token wpisany do niej byłby tokenem usługi.
	if session == 0 {
		return 0, choice, noop, errors.New("sesja 0 (usług) nie jest sesją użytkownika")
	}
	uinfo, ierr := ops.inspect(user)
	if ierr != nil {
		// Bez odczytu tokenu nie wiemy, czy jest podniesiony; nie oddajemy go pomocnikowi w ciemno.
		return 0, choice, noop, fmt.Errorf("nie udało się odczytać cech tokenu użytkownika: %w", ierr)
	}
	et, etErr := ops.elevationType(user)
	if etErr == nil {
		choice.Elevation = elevationName(et)
	}
	// Token jest podniesiony, gdy mówi to typ podniesienia, flaga TOKEN_ELEVATION, włączona grupa Administratorzy albo wysoka
	// integralność: każda z tych oznak wystarcza, żeby nie oddać go pomocnikowi bez odchudzenia.
	elevated := uinfo.Elevated || uinfo.AdminEnabled || uinfo.IntegrityRID >= wintoken.RIDHigh ||
		(etErr == nil && et == elevationFull)

	c := &chooser{ops: ops, user: user, session: session, uinfo: uinfo, elevated: elevated}

	fallback := func(reason string) (windows.Token, TokenChoice, func(), error) {
		t, lowered, err := c.mediumToken()
		if err != nil {
			return 0, choice, noop, fmt.Errorf("%s; zapas niemożliwy, pomocnik nie wystartuje: %w", reason, err)
		}
		choice.Kind, choice.Reason, choice.Fallback, choice.Lowered = TokenUserFallback, reason, true, lowered
		choice = c.describe(choice, t)
		return t, choice, c.closer(t), nil
	}

	switch level {
	case config.DesktopHelperUser:
		t, lowered, err := c.mediumToken()
		if err != nil {
			return 0, choice, noop, fmt.Errorf("token średniej integralności: %w", err)
		}
		choice.Kind, choice.Lowered = TokenUserRequested, lowered
		choice.Reason = "poziom „user” wybrany w konfiguracji"
		if lowered {
			choice.Reason += " (token użytkownika był podniesiony: odchudzony do średniej integralności, bez uprawnień i bez grup administratorów)"
		}
		choice = c.describe(choice, t)
		return t, choice, c.closer(t), nil

	case config.DesktopHelperAdmin:
		t, kind, reason, err := c.adminToken(et, etErr)
		if err != nil {
			return fallback(err.Error())
		}
		if kind == TokenUserStandard {
			choice.Kind, choice.Reason, choice.Fallback = kind, reason, true
			choice = c.describe(choice, user)
			return user, choice, noop, nil
		}
		choice.Kind, choice.Reason = kind, reason
		choice = c.describe(choice, t)
		return t, choice, c.closer(t), nil

	default: // integrity
		t, err := c.integrityToken()
		if err != nil {
			return fallback(err.Error())
		}
		choice.Kind = TokenIntegrity
		choice.Reason = "zwykły (filtrowany) token użytkownika z podniesioną do wysokiej integralnością, bez grupy Administratorzy, z odjętymi uprawnieniami"
		choice = c.describe(choice, t)
		return t, choice, c.closer(t), nil
	}
}

// chooser trzyma kontekst jednego wyboru.
type chooser struct {
	ops      tokenOps
	user     windows.Token
	session  uint32
	uinfo    wintoken.Info
	elevated bool
}

func (c *chooser) closer(t windows.Token) func() {
	if t == c.user {
		return func() {}
	}
	return func() { c.ops.closeToken(t) }
}

// describe uzupełnia opis wyboru cechami tokenu, który naprawdę trafi do pomocnika.
func (c *chooser) describe(ch TokenChoice, t windows.Token) TokenChoice {
	info := c.uinfo
	if t != c.user {
		if i, err := c.ops.inspect(t); err == nil {
			info = i
		}
	}
	ch.Integrity, ch.AdminGroup = wintoken.IntegrityName(info.IntegrityRID), info.AdminEnabled
	return ch
}

// expect opisuje, jaki ma być wynik.
type expect struct {
	integrity    uint32 // dokładny poziom integralności (0 = bez wymagania)
	maxIntegrity uint32 // górna granica (0 = bez wymagania)
	adminAllowed bool   // czy włączona grupa Administratorzy jest dopuszczalna
}

// verify porównuje token z tokenem użytkownika i oczekiwaniami; jedyny sposób, w jaki token trafia do CreateProcessAsUser.
func (c *chooser) verify(t windows.Token, e expect) error {
	info, err := c.ops.inspect(t)
	if err != nil {
		return fmt.Errorf("nie udało się zweryfikować tokenu pomocnika: %w", err)
	}
	if info.UserSID != c.uinfo.UserSID {
		return errors.New("TokenUser wyniku różni się od użytkownika sesji")
	}
	if info.Session != c.session {
		return fmt.Errorf("TokenSessionId wyniku (%d) różni się od sesji użytkownika (%d)", info.Session, c.session)
	}
	if e.integrity != 0 && info.IntegrityRID != e.integrity {
		return fmt.Errorf("integralność wyniku %s (0x%X), oczekiwano %s (0x%X)", wintoken.IntegrityName(info.IntegrityRID), info.IntegrityRID, wintoken.IntegrityName(e.integrity), e.integrity)
	}
	if e.maxIntegrity != 0 && info.IntegrityRID > e.maxIntegrity {
		return fmt.Errorf("integralność wyniku %s (0x%X) przekracza średnią", wintoken.IntegrityName(info.IntegrityRID), info.IntegrityRID)
	}
	if !e.adminAllowed && info.AdminEnabled {
		return errors.New("wynik ma włączoną grupę Administratorzy")
	}
	return nil
}

// primaryInSession tworzy niezależną kopię główną tokenu użytkownika i dba, żeby była w sesji użytkownika.
func (c *chooser) primaryInSession(src windows.Token) (windows.Token, error) {
	p, err := c.ops.toPrimary(src)
	if err != nil {
		hint := ""
		if errors.Is(err, windows.ERROR_BAD_IMPERSONATION_LEVEL) {
			hint = " (token ma poziom identyfikacji: wołający nie ma SeTcbPrivilege, czyli nie działa jako SYSTEM)"
		}
		return 0, fmt.Errorf("DuplicateTokenEx nieudane: %w%s", err, hint)
	}
	info, err := c.ops.inspect(p)
	if err != nil || info.Session != c.session {
		// Token (zwłaszcza połączony) potrafi mieć inną sesję niż użytkownika; proces ma działać w sesji jego pulpitu.
		if err := c.ops.setSession(p, c.session); err != nil {
			c.ops.closeToken(p)
			return 0, fmt.Errorf("ustawienie sesji %d nieudane (SeTcbPrivilege?): %w", c.session, err)
		}
	}
	return p, nil
}

// integrityToken buduje token poziomu „integrity”: filtrowany token użytkownika → kopia główna → odjęcie uprawnień → wysoka
// integralność. Dla tokenu podniesionego (UAC wyłączone) odjęcie robi też LUA_TOKEN, żeby grupa Administratorzy była „tylko do
// odmowy”. Wynik jest weryfikowany; błąd zamyka wszystko, co utworzono.
func (c *chooser) integrityToken() (windows.Token, error) {
	p, err := c.primaryInSession(c.user)
	if err != nil {
		return 0, err
	}
	r, err := c.ops.restrict(p, c.elevated)
	c.ops.closeToken(p)
	if err != nil {
		return 0, fmt.Errorf("odjęcie uprawnień nieudane: %w", err)
	}
	if err := c.ops.setIntegrity(r, wintoken.RIDHigh); err != nil {
		c.ops.closeToken(r)
		return 0, fmt.Errorf("podniesienie integralności do wysokiej nieudane (SeTcbPrivilege?): %w", err)
	}
	if err := c.verify(r, expect{integrity: wintoken.RIDHigh}); err != nil {
		c.ops.closeToken(r)
		return 0, err
	}
	return r, nil
}

// mediumToken zwraca token średniej integralności dla poziomu „user” i dla zapasu. Token niepodniesiony zwracamy bez zmian
// (jak w 0.4.2). Token podniesiony (UAC wyłączone, wbudowany administrator) NIGDY nie jest oddawany pełny: dostaje LUA_TOKEN,
// odjęcie uprawnień i integralność średnią; jeśli się nie da, jest błąd (wołający odmawia startu).
func (c *chooser) mediumToken() (t windows.Token, lowered bool, err error) {
	if !c.elevated {
		return c.user, false, nil
	}
	p, err := c.primaryInSession(c.user)
	if err != nil {
		return 0, false, err
	}
	r, err := c.ops.restrict(p, true)
	c.ops.closeToken(p)
	if err != nil {
		return 0, false, fmt.Errorf("odchudzenie podniesionego tokenu nieudane: %w", err)
	}
	if err := c.ops.setIntegrity(r, wintoken.RIDMedium); err != nil {
		c.ops.closeToken(r)
		return 0, false, fmt.Errorf("obniżenie integralności nieudane: %w", err)
	}
	if err := c.verify(r, expect{maxIntegrity: wintoken.RIDMedium}); err != nil {
		c.ops.closeToken(r)
		return 0, false, err
	}
	return r, true, nil
}

// adminToken buduje token poziomu „admin”: połączony token UAC (Limited) albo pełny token (Full), z odjętymi uprawnieniami.
// Na koncie standardowym (Default bez podniesienia) nie ma czego podnosić: kind = TokenUserStandard i reason mówi to wprost.
func (c *chooser) adminToken(et uint32, etErr error) (tok windows.Token, kind, reason string, err error) {
	if etErr != nil {
		return 0, "", "", fmt.Errorf("nie udało się odczytać typu podniesienia tokenu: %w", etErr)
	}
	switch {
	case et == elevationLimited:
		linked, err := c.ops.linkedToken(c.user)
		if err != nil {
			return 0, "", "", fmt.Errorf("brak połączonego tokenu administratora (TokenLinkedToken): %w", err)
		}
		primary, err := c.primaryInSession(linked)
		c.ops.closeToken(linked)
		if err != nil {
			return 0, "", "", err
		}
		restricted, err := c.ops.restrict(primary, false)
		c.ops.closeToken(primary)
		if err != nil {
			return 0, "", "", fmt.Errorf("odjęcie uprawnień tokenu administratora nieudane: %w", err)
		}
		if err := c.verify(restricted, expect{adminAllowed: true}); err != nil {
			c.ops.closeToken(restricted)
			return 0, "", "", err
		}
		return restricted, TokenAdminLinked, "połączony (podniesiony) token UAC tego samego użytkownika, z odjętymi uprawnieniami", nil

	case c.elevated:
		dup, err := c.primaryInSession(c.user)
		if err != nil {
			return 0, "", "", fmt.Errorf("kopia pełnego tokenu nieudana: %w", err)
		}
		restricted, err := c.ops.restrict(dup, false)
		c.ops.closeToken(dup)
		if err != nil {
			return 0, "", "", fmt.Errorf("odjęcie uprawnień pełnego tokenu nieudane: %w", err)
		}
		if err := c.verify(restricted, expect{adminAllowed: true}); err != nil {
			c.ops.closeToken(restricted)
			return 0, "", "", err
		}
		return restricted, TokenAdminFull, "token użytkownika jest już pełny (UAC wyłączone albo wbudowany administrator), z odjętymi uprawnieniami", nil

	default:
		return c.user, TokenUserStandard, "konto standardowe: nie ma tokenu administratora do użycia, pomocnik dostaje token użytkownika (poziom „integrity” działa także na koncie standardowym)", nil
	}
}

func elevationName(et uint32) string {
	switch et {
	case elevationDefault:
		return "default"
	case elevationFull:
		return "full"
	case elevationLimited:
		return "limited"
	}
	return "unknown"
}

// realTokenOps to operacje na prawdziwych tokenach Windows.
func realTokenOps() tokenOps {
	return tokenOps{
		elevationType: func(t windows.Token) (uint32, error) {
			var typ, n uint32
			if err := windows.GetTokenInformation(t, windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), 4, &n); err != nil {
				return 0, err
			}
			return typ, nil
		},
		linkedToken: func(t windows.Token) (windows.Token, error) {
			var linked windows.Token
			var n uint32
			if err := windows.GetTokenInformation(t, windows.TokenLinkedToken, (*byte)(unsafe.Pointer(&linked)), uint32(unsafe.Sizeof(linked)), &n); err != nil {
				return 0, err
			}
			return linked, nil
		},
		toPrimary:    wintoken.ToPrimary,
		setSession:   wintoken.SetSession,
		restrict:     wintoken.Restrict,
		setIntegrity: wintoken.SetIntegrity,
		inspect:      wintoken.Inspect,
		closeToken: func(t windows.Token) {
			if t != 0 {
				_ = t.Close()
			}
		},
	}
}
