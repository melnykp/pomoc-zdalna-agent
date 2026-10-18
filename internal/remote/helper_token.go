package remote

import "fmt"

// Rodzaje wybranego tokenu pomocnika (TokenChoice.Kind): w dzienniku, w testach i w raporcie do serwera (helper_token).
const (
	// TokenIntegrity: zwykły (filtrowany) token użytkownika z podniesioną do wysokiej integralnością i odjętymi uprawnieniami, BEZ
	// włączonej grupy Administratorzy. Domyślny; działa także na koncie standardowym.
	TokenIntegrity = "integrity"
	// TokenAdminLinked: połączony (podniesiony) token UAC tego samego użytkownika, z odjętymi uprawnieniami (poziom „admin”).
	TokenAdminLinked = "admin-linked"
	// TokenAdminFull: token użytkownika jest już pełny (UAC wyłączone albo wbudowany administrator), z odjętymi uprawnieniami.
	TokenAdminFull = "admin-full"
	// TokenUserStandard: poziom „admin” na koncie standardowym, nie ma tokenu podniesionego do użycia.
	TokenUserStandard = "user-standard"
	// TokenUserRequested: poziom „user” wybrany w konfiguracji (średnia integralność).
	TokenUserRequested = "user-requested"
	// TokenUserFallback: miał być poziom „integrity” albo „admin”, ale się nie udało; pomocnik dostaje token średniej integralności.
	TokenUserFallback = "user-fallback"
)

// TokenChoice opisuje, jaki token dostał pomocnik i dlaczego; trafia do dziennika agenta (Info albo Warn przy zapasie) i do
// raportu dla serwera.
type TokenChoice struct {
	Kind   string
	Level  string // poziom z konfiguracji (config.DesktopHelper*)
	Reason string
	// Elevation to typ podniesienia tokenu użytkownika z WTSQueryUserToken: default | full | limited | unknown.
	Elevation string
	// Fallback mówi, że poziom z konfiguracji nie został osiągnięty (wtedy logujemy jako ostrzeżenie).
	Fallback bool
	// Integrity i AdminGroup opisują token faktycznie przekazany pomocnikowi (high | medium…, grupa Administratorzy włączona).
	Integrity  string
	AdminGroup bool
	// Lowered: token użytkownika był podniesiony (UAC wyłączone / wbudowany administrator) i został odchudzony do średniej
	// integralności bez uprawnień i bez włączonych grup administratorów.
	Lowered bool
}

// HelperStatus to stan pomocnika do raportu dla serwera.
type HelperStatus struct {
	// Level to poziom, z którym silnik działa od startu agenta (stały poziom komputera).
	Level string
	// Token i Fallback opisują ostatni start pomocnika (puste przed pierwszym).
	Token    string
	Fallback bool
	// SessionLevel to poziom podniesiony na czas trwającej sesji za zgodą użytkownika (integrity); pusty, gdy nie ma podniesienia.
	SessionLevel string
	// UAC to "on", "off" (UAC wyłączony: poziom user nie chroni okien administratora) albo pusty tekst (nieznany).
	UAC string
}

// String składa jedną linię do dziennika.
func (c TokenChoice) String() string {
	s := fmt.Sprintf("token=%s level=%s elevation=%s integrity=%s admin_group=%v", c.Kind, c.Level, c.Elevation, c.Integrity, c.AdminGroup)
	if c.Lowered {
		s += " lowered=true"
	}
	return s
}
