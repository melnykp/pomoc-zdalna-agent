//go:build windows

// Package wintoken odczytuje i zmienia cechy tokenów Windows potrzebne do decyzji, z jakimi uprawnieniami uruchomić pomocnika
// pulpitu: kto jest użytkownikiem tokenu, w której sesji jest token, jaki ma poziom integralności i czy grupa Administratorzy
// jest w nim włączona (a nie tylko „do odmowy”, jak w tokenie filtrowanym UAC).
package wintoken

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Poziomy integralności (RID z SID etykiety obowiązkowej S-1-16-<RID>).
const (
	RIDLow    = 0x1000
	RIDMedium = 0x2000
	RIDHigh   = 0x3000
	RIDSystem = 0x4000
)

// Atrybuty grup w tokenie i flagi CreateRestrictedToken.
const (
	seGroupEnabled      = 0x00000004
	seGroupDenyOnly     = 0x00000010
	seGroupIntegrity    = 0x00000020
	DisableMaxPrivilege = 0x1 // CreateRestrictedToken: usuń wszystkie uprawnienia poza SeChangeNotifyPrivilege
	LUAToken            = 0x4 // CreateRestrictedToken: token filtrowany jak w UAC (grupy administratorów „tylko do odmowy”)
)

// Info to cechy tokenu istotne dla bezpieczeństwa pomocnika.
type Info struct {
	UserSID      string
	Session      uint32
	IntegrityRID uint32
	// AdminEnabled: grupa Administratorzy (S-1-5-32-544) jest w tokenie WŁĄCZONA (token podniesiony). W tokenie filtrowanym UAC
	// ta grupa jest, ale „tylko do odmowy”, więc to pole jest false.
	AdminEnabled bool
	// Elevated: TOKEN_ELEVATION mówi, że token jest podniesiony.
	Elevated bool
	// Restricted: token ma SID-y ograniczające (drugi przebieg sprawdzania dostępu).
	Restricted bool
}

// IntegrityName zamienia RID poziomu integralności na nazwę.
func IntegrityName(rid uint32) string {
	switch {
	case rid >= RIDSystem:
		return "system"
	case rid >= RIDHigh:
		return "high"
	case rid >= RIDMedium:
		return "medium"
	case rid >= RIDLow:
		return "low"
	case rid == 0:
		return "unknown"
	}
	return "untrusted"
}

var (
	advapi                = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestricted  = advapi.NewProc("CreateRestrictedToken")
	procIsTokenRestricted = advapi.NewProc("IsTokenRestricted")
)

// Inspect odczytuje cechy tokenu. Błąd oznacza, że nie da się ich zweryfikować, a wtedy wołający nie powinien ufać tokenowi.
func Inspect(t windows.Token) (Info, error) {
	var in Info
	u, err := t.GetTokenUser()
	if err != nil {
		return in, fmt.Errorf("TokenUser: %w", err)
	}
	in.UserSID = u.User.Sid.String()
	var n uint32
	if err := windows.GetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&in.Session)), 4, &n); err != nil {
		return in, fmt.Errorf("TokenSessionId: %w", err)
	}
	rid, err := integrity(t)
	if err != nil {
		return in, err
	}
	in.IntegrityRID = rid
	groups, err := t.GetTokenGroups()
	if err != nil {
		return in, fmt.Errorf("TokenGroups: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return in, fmt.Errorf("SID Administratorów: %w", err)
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(admins) && g.Attributes&seGroupEnabled != 0 && g.Attributes&seGroupDenyOnly == 0 {
			in.AdminEnabled = true
		}
	}
	in.Elevated = t.IsElevated()
	r, _, _ := procIsTokenRestricted.Call(uintptr(t))
	in.Restricted = r != 0
	return in, nil
}

func integrity(t windows.Token) (uint32, error) {
	var n uint32
	_ = windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0, fmt.Errorf("TokenIntegrityLevel: brak danych")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, fmt.Errorf("TokenIntegrityLevel: %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return 0, fmt.Errorf("TokenIntegrityLevel: pusty SID")
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1), nil
}

// SetIntegrity ustawia poziom integralności tokenu. Obniżenie jest zawsze dozwolone; PODNIESIENIE ponad obecny poziom
// wymaga, żeby wołający proces miał włączone SeTcbPrivilege (usługa SYSTEM je ma, zwykły proces nie).
func SetIntegrity(t windows.Token, rid uint32) error {
	sid, err := windows.StringToSid(fmt.Sprintf("S-1-16-%d", rid))
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: sid, Attributes: seGroupIntegrity}}
	size := uint32(unsafe.Sizeof(label)) + windows.GetLengthSid(sid)
	return windows.SetTokenInformation(t, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), size)
}

// Restrict zwraca kopię głównego tokenu bez uprawnień (CreateRestrictedToken z DISABLE_MAX_PRIVILEGE; zostaje tylko
// SeChangeNotifyPrivilege), a przy lua dodatkowo z grupami administratorów „tylko do odmowy” (LUA_TOKEN). Poziom integralności,
// użytkownik i sesja zostają. Bez SID-ów ograniczających, więc sprawdzenia dostępu zachowują się jak dla pełnego tokenu.
func Restrict(t windows.Token, lua bool) (windows.Token, error) {
	flags := uintptr(DisableMaxPrivilege)
	if lua {
		flags |= LUAToken
	}
	var out windows.Token
	r, _, e := procCreateRestricted.Call(uintptr(t), flags, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", e)
	}
	return out, nil
}

// ToPrimary zwraca niezależną kopię tokenu jako token główny (do CreateProcessAsUser).
func ToPrimary(t windows.Token) (windows.Token, error) {
	var dup windows.Token
	if err := windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, err
	}
	return dup, nil
}

// SetSession ustawia sesję tokenu (wymaga SeTcbPrivilege).
func SetSession(t windows.Token, session uint32) error {
	return windows.SetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4)
}
