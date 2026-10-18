//go:build windows

package winput

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
	procGetWindowThreadPID  = user32.NewProc("GetWindowThreadProcessId")
	procGetProcessWinStn    = user32.NewProc("GetProcessWindowStation")
)

// Poziomy integralności (RID z SID etykiety obowiązkowej).
const (
	ridLow    = 0x1000
	ridMedium = 0x2000
	ridHigh   = 0x3000
	ridSystem = 0x4000
)

// IntegrityName zamienia RID poziomu integralności na nazwę.
func IntegrityName(rid uint32) string {
	switch {
	case rid >= ridSystem:
		return "system"
	case rid >= ridHigh:
		return "high"
	case rid >= ridMedium:
		return "medium"
	case rid >= ridLow:
		return "low"
	case rid == 0:
		return "unknown"
	}
	return "untrusted"
}

// ProcessContext opisuje, w jakim kontekście działa pomocnik: kto, z jakimi uprawnieniami i na jakim pulpicie. SendInput jest
// zależny od wszystkich trzech (UIPI blokuje wejście do okien o wyższym poziomie integralności, pulpit wątku musi być wejściowym).
type ProcessContext struct {
	PID            uint32 `json:"pid"`
	User           string `json:"user"`
	SessionID      uint32 `json:"session"`
	IntegrityRID   uint32 `json:"integrity_rid"`
	Integrity      string `json:"integrity"`
	Elevated       bool   `json:"elevated"`
	ElevationType  string `json:"elevation_type"` // default | full | limited
	WindowStation  string `json:"window_station"`
	ThreadDesktop  string `json:"thread_desktop"`
	InputDesktop   string `json:"input_desktop"`
	InputDesktopOK bool   `json:"input_desktop_ok"`
}

// String to jedna linia do dziennika.
func (c ProcessContext) String() string {
	return fmt.Sprintf("użytkownik=%s sesja=%d integralność=%s(0x%X) podniesiony=%v typ=%s stacja=%q pulpit wątku=%q pulpit wejściowy=%q",
		c.User, c.SessionID, c.Integrity, c.IntegrityRID, c.Elevated, c.ElevationType, c.WindowStation, c.ThreadDesktop, c.InputDesktop)
}

// tokenIntegrity zwraca RID poziomu integralności tokenu (0, gdy nie da się odczytać).
func tokenIntegrity(t windows.Token) uint32 {
	var n uint32
	_ = windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return 0
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1)
}

func elevationType(t windows.Token) string {
	var typ uint32
	var n uint32
	if err := windows.GetTokenInformation(t, windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), 4, &n); err != nil {
		return "unknown"
	}
	switch typ {
	case 1:
		return "default"
	case 2:
		return "full"
	case 3:
		return "limited"
	}
	return "unknown"
}

// Context odczytuje kontekst bieżącego procesu i wątku. Wołać z wątku, który wstrzykuje wejście (pulpit wątku).
func Context() ProcessContext {
	c := ProcessContext{PID: windows.GetCurrentProcessId()}
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		account, domain, _, lerr := u.User.Sid.LookupAccount("")
		if lerr == nil {
			c.User = domain + "\\" + account
		} else {
			c.User = u.User.Sid.String()
		}
	}
	_ = windows.ProcessIdToSessionId(c.PID, &c.SessionID)
	c.IntegrityRID = tokenIntegrity(tok)
	c.Integrity = IntegrityName(c.IntegrityRID)
	c.Elevated = tok.IsElevated()
	c.ElevationType = elevationType(tok)
	if h, _, _ := procGetProcessWinStn.Call(); h != 0 {
		c.WindowStation = userObjectName(h)
	}
	c.ThreadDesktop = ThreadDesktopName()
	if n, err := InputDesktopName(); err == nil {
		c.InputDesktop, c.InputDesktopOK = n, true
	}
	return c
}

func userObjectName(h uintptr) string {
	var buf [256]uint16
	var need uint32
	if r, _, _ := procGetUOI.Call(h, 2, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&need))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

// ForegroundInfo opisuje proces okna na pierwszym planie. UIPI po cichu odrzuca wejście wstrzykiwane do okna o wyższym
// poziomie integralności niż nasz (SendInput zwraca sukces), więc to jest główny podejrzany przy „wejście nie działa”.
type ForegroundInfo struct {
	Exe       string `json:"exe,omitempty"` // tylko nazwa pliku, bez ścieżki i bez tytułu okna
	PID       uint32 `json:"pid,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	// Higher: proces okna ma wyższy poziom integralności niż pomocnik albo nie dało się go odczytać (odmowa dostępu).
	Higher bool `json:"higher"`
	// Unreadable: nie udało się otworzyć procesu okna (zwykle właśnie przez wyższe uprawnienia).
	Unreadable bool `json:"unreadable,omitempty"`
}

// Foreground odczytuje proces okna na pierwszym planie i porównuje jego poziom integralności z podanym (naszym).
func Foreground(ownRID uint32) ForegroundInfo {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ForegroundInfo{}
	}
	var pid uint32
	procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	info := ForegroundInfo{PID: pid}
	if pid == 0 {
		return info
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		info.Unreadable, info.Higher = true, true
		return info
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_PATH]uint16
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
		info.Exe = filepath.Base(windows.UTF16ToString(buf[:n]))
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		info.Unreadable, info.Higher = true, true
		return info
	}
	defer tok.Close()
	rid := tokenIntegrity(tok)
	info.Integrity = IntegrityName(rid)
	info.Higher = rid > ownRID
	return info
}
