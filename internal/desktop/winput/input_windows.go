//go:build windows

package winput

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procSendInput     = user32.NewProc("SendInput")
	procGetSystemMet  = user32.NewProc("GetSystemMetrics")
	procGetCursorPos  = user32.NewProc("GetCursorPos")
	procOpenInputDesk = user32.NewProc("OpenInputDesktop")
	procCloseDesktop  = user32.NewProc("CloseDesktop")
	procGetUOI        = user32.NewProc("GetUserObjectInformationW")
	procGetThreadDesk = user32.NewProc("GetThreadDesktop")
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	evMove       = 0x0001
	evLeftDown   = 0x0002
	evLeftUp     = 0x0004
	evRightDown  = 0x0008
	evRightUp    = 0x0010
	evMiddleDown = 0x0020
	evMiddleUp   = 0x0040
	evXDown      = 0x0080
	evXUp        = 0x0100
	evWheel      = 0x0800
	evHWheel     = 0x1000
	evVirtDesk   = 0x4000
	evAbsolute   = 0x8000

	keyExtended = 0x0001
	keyUp       = 0x0002
	keyScan     = 0x0008

	smXVirtual  = 76
	smYVirtual  = 77
	smCXVirtual = 78
	smCYVirtual = 79
)

type mouseInputT struct {
	typ       uint32
	_         uint32
	dx, dy    int32
	mouseData uint32
	flags     uint32
	time      uint32
	_         uint32
	extra     uintptr
}

type keyInputT struct {
	typ   uint32
	_     uint32
	vk    uint16
	scan  uint16
	flags uint32
	time  uint32
	_     uint32
	extra uintptr
	_     [8]byte
}

// Injector wstrzykuje wejście; współrzędne znormalizowane odnoszą się do monitora o prostokącie Mon.
type Injector struct {
	MonLeft, MonTop, MonW, MonH int

	// Check dostaje po każdym ruchu myszy cel i położenie kursora odczytane zaraz po SendInput. Rozbieżność (kursor się
	// nie przesunął) to ślad po cichym odrzuceniu wejścia (UIPI, zły pulpit); SendInput w takim razie zwykle zgłasza sukces.
	Check func(wantX, wantY, gotX, gotY int)

	mu sync.Mutex
}

// SetMonitor zmienia monitor, względem którego liczone są współrzędne 0..1 (atomowo względem ruchów myszy).
func (j *Injector) SetMonitor(left, top, w, h int) {
	j.mu.Lock()
	j.MonLeft, j.MonTop, j.MonW, j.MonH = left, top, w, h
	j.mu.Unlock()
}

func (j *Injector) monitor() (left, top, w, h int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.MonLeft, j.MonTop, j.MonW, j.MonH
}

// SendInputError to nieudane wywołanie SendInput razem z kontekstem potrzebnym do diagnozy: kod błędu systemu oraz pulpit
// wątku i pulpit wejściowy (SendInput działa na pulpicie wątku; ERROR_ACCESS_DENIED przy innym niż wejściowy).
type SendInputError struct {
	Op            string // "mysz" | "klawisz"
	Errno         syscall.Errno
	Sent          uintptr // ile zdarzeń przyjął system (0 przy błędzie)
	ThreadDesktop string
	InputDesktop  string
}

func (e *SendInputError) Error() string {
	return fmt.Sprintf("SendInput(%s): przyjęto %d z 1, błąd systemu %d (%v), pulpit wątku %q, pulpit wejściowy %q", e.Op, e.Sent, uint32(e.Errno), e.Errno, e.ThreadDesktop, e.InputDesktop)
}

// IsAccessDenied mówi, czy system odmówił dostępu (zły pulpit albo poziom uprawnień).
func (e *SendInputError) IsAccessDenied() bool { return e.Errno == syscall.ERROR_ACCESS_DENIED }

// virtualScreen zwraca prostokąt całego pulpitu wirtualnego.
func virtualScreen() (x, y, w, h int) {
	get := func(i uintptr) int { r, _, _ := procGetSystemMet.Call(i); return int(int32(r)) }
	return get(smXVirtual), get(smYVirtual), get(smCXVirtual), get(smCYVirtual)
}

func sendMouse(in mouseInputT) error {
	in.typ = inputMouse
	r, _, e := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	if r != 1 {
		return newSendInputError("mysz", r, e)
	}
	return nil
}

func sendKey(in keyInputT) error {
	in.typ = inputKeyboard
	r, _, e := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	if r != 1 {
		return newSendInputError("klawisz", r, e)
	}
	return nil
}

func newSendInputError(op string, sent uintptr, e error) *SendInputError {
	errno, _ := e.(syscall.Errno)
	in, _ := InputDesktopName()
	return &SendInputError{Op: op, Errno: errno, Sent: sent, ThreadDesktop: ThreadDesktopName(), InputDesktop: in}
}

// Move ustawia kursor w punkcie (nx, ny) w skali 0..1 względem monitora.
func (j *Injector) Move(nx, ny float64) error {
	left, top, w, h := j.monitor()
	px := NormToPixel(nx, left, w)
	py := NormToPixel(ny, top, h)
	vx, vy, vw, vh := virtualScreen()
	err := sendMouse(mouseInputT{
		dx: int32(AbsCoord(px, vx, vw)), dy: int32(AbsCoord(py, vy, vh)),
		flags: evMove | evAbsolute | evVirtDesk,
	})
	if err == nil && j.Check != nil {
		gx, gy := CursorPos()
		j.Check(px, py, gx, gy)
	}
	return err
}

// Button naciska (down) lub puszcza przycisk myszy: 0 lewy, 1 środkowy, 2 prawy, 3 wstecz, 4 dalej.
func (j *Injector) Button(b int, down bool) error {
	in := mouseInputT{}
	switch b {
	case 0:
		in.flags = pick(down, evLeftDown, evLeftUp)
	case 1:
		in.flags = pick(down, evMiddleDown, evMiddleUp)
	case 2:
		in.flags = pick(down, evRightDown, evRightUp)
	case 3, 4:
		in.flags = pick(down, evXDown, evXUp)
		in.mouseData = uint32(b - 2) // XBUTTON1=1, XBUTTON2=2
	default:
		return fmt.Errorf("nieznany przycisk %d", b)
	}
	return sendMouse(in)
}

// Wheel przewija; wartości w jednostkach WHEEL_DELTA (120 na „ząbek”), dy>0 w górę.
func (j *Injector) Wheel(dx, dy int) error {
	if dy != 0 {
		if err := sendMouse(mouseInputT{flags: evWheel, mouseData: uint32(int32(dy))}); err != nil {
			return err
		}
	}
	if dx != 0 {
		return sendMouse(mouseInputT{flags: evHWheel, mouseData: uint32(int32(dx))})
	}
	return nil
}

// Key wciska lub puszcza klawisz fizyczny wskazany przez KeyboardEvent.code.
func (j *Injector) Key(code string, down bool) error {
	s, ok := LookupScan(code)
	if !ok {
		return fmt.Errorf("nieznany klawisz %q", code)
	}
	in := keyInputT{scan: s.Code, flags: keyScan}
	if s.Extended {
		in.flags |= keyExtended
	}
	if !down {
		in.flags |= keyUp
	}
	return sendKey(in)
}

func pick(down bool, d, u uint32) uint32 {
	if down {
		return d
	}
	return u
}

// CursorPos zwraca położenie kursora w pikselach pulpitu (do weryfikacji w testach).
func CursorPos() (x, y int) {
	var p struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	return int(p.X), int(p.Y)
}

var (
	procWindowFromPoint = user32.NewProc("WindowFromPoint")
	procGetAncestor     = user32.NewProc("GetAncestor")
	procGetForeground   = user32.NewProc("GetForegroundWindow")
)

// RootWindowAtCursor zwraca okno najwyższego poziomu pod kursorem (0, gdy brak). Służy jako zabezpieczenie testów:
// kliknięcie wstrzykujemy tylko wtedy, gdy pod kursorem jest oczekiwane okno testowe, a nie okno użytkownika.
func RootWindowAtCursor() uintptr {
	var p struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	// WindowFromPoint przyjmuje POINT przekazany w całości (8 bajtów) w jednym rejestrze.
	h, _, _ := procWindowFromPoint.Call(uintptr(uint64(uint32(p.X)) | uint64(uint32(p.Y))<<32))
	if h == 0 {
		return 0
	}
	const gaRoot = 2
	r, _, _ := procGetAncestor.Call(h, gaRoot)
	return r
}

// ForegroundRoot zwraca okno pierwszego planu (to ono dostaje wstrzyknięte klawisze).
func ForegroundRoot() uintptr {
	h, _, _ := procGetForeground.Call()
	return h
}

// InputDesktopName zwraca nazwę pulpitu wejściowego ("Default", "Winlogon" dla ekranu logowania/UAC) albo błąd,
// gdy proces nie ma do niego dostępu (zwykły proces użytkownika podczas ekranu bezpiecznego).
func InputDesktopName() (string, error) {
	const genericRead = 0x80000000
	h, _, e := procOpenInputDesk.Call(0, 0, genericRead)
	if h == 0 {
		return "", fmt.Errorf("OpenInputDesktop: %v", e)
	}
	defer procCloseDesktop.Call(h)
	var buf [256]uint16
	var need uint32
	const uoiName = 2
	r, _, e := procGetUOI.Call(h, uoiName, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return "", fmt.Errorf("GetUserObjectInformation: %v", e)
	}
	return windows.UTF16ToString(buf[:]), nil
}

// ThreadDesktopName zwraca nazwę pulpitu przypisanego do bieżącego wątku.
func ThreadDesktopName() string {
	tid := windows.GetCurrentThreadId()
	h, _, _ := procGetThreadDesk.Call(uintptr(tid))
	if h == 0 {
		return ""
	}
	var buf [256]uint16
	var need uint32
	r, _, _ := procGetUOI.Call(h, 2, uintptr(unsafe.Pointer(&buf[0])), unsafe.Sizeof(buf), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}
