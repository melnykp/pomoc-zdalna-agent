//go:build windows

package capture

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenInputDesktopC = user32.NewProc("OpenInputDesktop")
	procCloseDesktopC     = user32.NewProc("CloseDesktop")
	procSetThreadDesktop  = user32.NewProc("SetThreadDesktop")
	procGetUserObjectInfo = user32.NewProc("GetUserObjectInformationW")
)

// Prawa do pulpitu potrzebne do przechwytywania i wstrzykiwania (GENERIC_ALL bywa odmawiane zwykłemu użytkownikowi).
const (
	desktopReadObjects   = 0x0001
	desktopCreateWindow  = 0x0002
	desktopWriteObjects  = 0x0080
	desktopSwitchDesktop = 0x0100
	genericAll           = 0x10000000
)

// ThreadDesktop dołącza bieżący wątek systemowy do pulpitu wejściowego (tego, który użytkownik ma teraz przed oczami).
// DuplicateOutput i BitBlt odmawiają dostępu (E_ACCESSDENIED), gdy wątek siedzi na innym pulpicie niż wejściowy, np.
// tuż po odblokowaniu, przy zgodzie UAC albo przy przełączaniu użytkownika. Wołać z wątku zablokowanego
// (runtime.LockOSThread); uchwyt pulpitu trzeba trzymać, dopóki wątek na nim pracuje, więc Close na końcu pracy.
type ThreadDesktop struct{ h uintptr }

// Attach otwiera pulpit wejściowy i przypisuje do niego wątek. Zwraca nazwę pulpitu ("Default", "Winlogon"…).
// Błąd nie jest fatalny dla wołającego: na zwykłym pulpicie użytkownika wątek i tak zwykle już na nim jest.
func (t *ThreadDesktop) Attach() (string, error) {
	h, _, e := procOpenInputDesktopC.Call(0, 0, genericAll)
	if h == 0 {
		h, _, e = procOpenInputDesktopC.Call(0, 0, desktopReadObjects|desktopCreateWindow|desktopWriteObjects|desktopSwitchDesktop)
	}
	if h == 0 {
		return "", fmt.Errorf("OpenInputDesktop: %v", e)
	}
	name := desktopName(h)
	if r, _, e := procSetThreadDesktop.Call(h); r == 0 {
		procCloseDesktopC.Call(h)
		return name, fmt.Errorf("SetThreadDesktop(%q): %v", name, e)
	}
	old := t.h
	t.h = h
	if old != 0 {
		procCloseDesktopC.Call(old)
	}
	return name, nil
}

// Close zwalnia uchwyt pulpitu. Wątek zostaje przypisany do niego do końca życia, więc po Close wątku nie używa się do
// niczego, co potrzebuje pulpitu (zwykle zamyka się go razem z wątkiem).
func (t *ThreadDesktop) Close() {
	if t.h != 0 {
		procCloseDesktopC.Call(t.h)
		t.h = 0
	}
}

func desktopName(h uintptr) string {
	var buf [256]uint16
	var need uint32
	const uoiName = 2
	if r, _, _ := procGetUserObjectInfo.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&need))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}
