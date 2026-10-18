//go:build windows

package remote

import (
	"context"
	"encoding/base64"
	"flag"
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/consent"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/wintoken"
)

var (
	user32Consent        = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows      = user32Consent.NewProc("EnumWindows")
	procEnumChildWindows = user32Consent.NewProc("EnumChildWindows")
	procGetWindowTextW   = user32Consent.NewProc("GetWindowTextW")
	procGetClassNameW    = user32Consent.NewProc("GetClassNameW")
	procGetWindowRect    = user32Consent.NewProc("GetWindowRect")
	procWindowFromPoint  = user32Consent.NewProc("WindowFromPoint")
	procWindowThreadPID  = user32Consent.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible  = user32Consent.NewProc("IsWindowVisible")
	procMessageBoxW      = user32Consent.NewProc("MessageBoxW")
	procPostMessageW     = user32Consent.NewProc("PostMessageW")
	procSetCursorPosT    = user32Consent.NewProc("SetCursorPos")
	procGetCursorPosT    = user32Consent.NewProc("GetCursorPos")
	procMouseEvent       = user32Consent.NewProc("mouse_event")
)

type rect struct{ left, top, right, bottom int32 }

// findWindow zwraca PID właściciela i uchwyt widocznego okna najwyższego poziomu o podanym tytule (0, 0, gdy brak).
func findWindow(title string) (uint32, uintptr) {
	var found uint32
	var foundHwnd uintptr
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		if v, _, _ := procIsWindowVisible.Call(hwnd); v == 0 {
			return 1
		}
		var buf [256]uint16
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 && windows.UTF16ToString(buf[:n]) == title {
			var pid uint32
			procWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
			found, foundHwnd = pid, hwnd
			return 0
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found, foundHwnd
}

// nthButton zwraca uchwyt i położenie n-tego (od 1) przycisku okna (w MessageBox z Tak/Nie: 1 = „Tak”, 2 = „Nie”). Klasa i położenie okien
// innych procesów są czytelne bez wysyłania im komunikatów.
func nthButton(dialog uintptr, n int) (uintptr, rect, bool) {
	var btn uintptr
	var r rect
	seen := 0
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var cls [32]uint16
		l, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&cls[0])), uintptr(len(cls)))
		if l > 0 && windows.UTF16ToString(cls[:l]) == "Button" {
			seen++
			if seen == n {
				btn = hwnd
				procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
				return 0
			}
		}
		return 1
	})
	procEnumChildWindows.Call(dialog, cb, 0)
	return btn, r, btn != 0
}

// hoverButton ustawia kursor na środku przycisku i potwierdza, że w tym punkcie naprawdę jest ten przycisk (WindowFromPoint), żeby
// nie kliknąć w cudze okno. Zwraca funkcję przywracającą kursor.
func hoverButton(btn uintptr, r rect) (restore func(), ok bool) {
	x, y := (r.left+r.right)/2, (r.top+r.bottom)/2
	var old struct{ x, y int32 }
	procGetCursorPosT.Call(uintptr(unsafe.Pointer(&old)))
	restore = func() { procSetCursorPosT.Call(uintptr(old.x), uintptr(old.y)) }
	procSetCursorPosT.Call(uintptr(x), uintptr(y))
	time.Sleep(100 * time.Millisecond)
	// WindowFromPoint przyjmuje POINT przekazany jako jedna wartość 64-bitowa (x w młodszej połowie).
	if h, _, _ := procWindowFromPoint.Call(uintptr(uint32(x)) | uintptr(uint32(y))<<32); h != btn {
		restore()
		return restore, false
	}
	return restore, true
}

// clickHere wstrzykuje kliknięcie lewym przyciskiem w bieżącym położeniu kursora (tak jak pomocnik: ścieżka SendInput, podlega UIPI).
func clickHere() {
	const leftDown, leftUp = 0x0002, 0x0004
	procMouseEvent.Call(leftDown, 0, 0, 0, 0)
	time.Sleep(60 * time.Millisecond)
	procMouseEvent.Call(leftUp, 0, 0, 0, 0)
}

func clickButton(btn uintptr, r rect) bool {
	restore, ok := hoverButton(btn, r)
	if !ok {
		return false
	}
	defer restore()
	clickHere()
	return true
}

const (
	mbYesNoCancel   = 0x00000003
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	idYes           = 6
)

func requireDesktop(t *testing.T) uint32 {
	t.Helper()
	if os.Getenv("RMM_DESKTOP_E2E") != "1" {
		t.Skip("ustaw RMM_DESKTOP_E2E=1: test pokazuje okna na pulpicie tego komputera i klika myszą")
	}
	proc.SetDPIAware() // współrzędne okien w pikselach fizycznych, jak w pomocniku
	waitForInputDesktop(t)
	session := windows.WTSGetActiveConsoleSessionId()
	var own uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own)
	if session == 0xFFFFFFFF || session != own {
		t.Skipf("konsola (sesja %d) to nie sesja testu (%d)", session, own)
	}
	return session
}

func ownPrimaryToken(t *testing.T) windows.Token {
	t.Helper()
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &self); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { self.Close() })
	return self
}

// Prawdziwy podproces "desktop-helper consent" (tu z tokenem średniej integralności tego procesu, bo wysoka wymaga usługi SYSTEM): pokazuje okno
// zgody, decyzja użytkownika (Tak, Nie) wraca przez potok, a brak odpowiedzi zabija podproces i zamyka okno. Sprawdza całą drogę poza
// samą integralnością: argumenty w base64, protokół ipc, limity czasu i sprzątanie.
func TestConsentProcessAllowDenyAndTimeout(t *testing.T) {
	session := requireDesktop(t)
	exe := buildHelperForTest(t)
	self := ownPrimaryToken(t)
	dup, err := wintoken.ToPrimary(self)
	if err != nil {
		t.Fatal(err)
	}
	defer dup.Close()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	launch := func(title, text string) (Process, error) {
		b64 := base64.StdEncoding.EncodeToString
		// Własny token procesu ograniczony do kopii: tak jak w teście wejścia (zwykły proces bez SeAssignPrimaryToken).
		r, rerr := wintoken.Restrict(self, false)
		if rerr != nil {
			return nil, rerr
		}
		defer r.Close()
		return startWithToken(r, dup, false, session, exe, log, "consent", b64([]byte(title)), b64([]byte(text)))
	}
	run := func(timeout time.Duration, act func(dialog uintptr) bool) (ConsentDecision, error) {
		type res struct {
			d   ConsentDecision
			err error
		}
		out := make(chan res, 1)
		go func() {
			d, err := askConsentWith(context.Background(), ConsentRequest{SessionID: "s", Engineer: "Inżynier Testowy", Timeout: timeout}, launch)
			out <- res{d, err}
		}()
		var wnd uintptr
		waitUntil(t, "okno zgody", func() bool { pid, w := findWindow(consentTitle); wnd = w; return pid != 0 })
		time.Sleep(500 * time.Millisecond)
		if act != nil && !act(wnd) {
			r := <-out // zostaw okno do końca czasu, nie klikamy na ślepo
			_ = r
			t.Skip("okno zgody przysłonięte (np. komputer zablokowany): kliknięcie nie trafiłoby w przycisk")
		}
		select {
		case r := <-out:
			return r.d, r.err
		case <-time.After(timeout + 15*time.Second):
			t.Fatal("pytanie o zgodę nie skończyło się w czasie")
		}
		return 0, nil
	}

	// Tak.
	d, err := run(30*time.Second, func(w uintptr) bool { b, r, ok := nthButton(w, 1); return ok && clickButton(b, r) })
	if err != nil || d != ConsentAllowed {
		t.Fatalf("Tak: %v err=%v", d, err)
	}
	waitUntil(t, "okno zamknięte po odpowiedzi", func() bool { pid, _ := findWindow(consentTitle); return pid == 0 })
	// Nie.
	d, err = run(30*time.Second, func(w uintptr) bool { b, r, ok := nthButton(w, 2); return ok && clickButton(b, r) })
	if err != nil || d != ConsentDenied {
		t.Fatalf("Nie: %v err=%v", d, err)
	}
	waitUntil(t, "okno zamknięte po odpowiedzi", func() bool { pid, _ := findWindow(consentTitle); return pid == 0 })
	// Brak odpowiedzi: po czasie odmowa, a podproces jest zabity, więc okno znika (nie wisi na ekranie użytkownika).
	d, err = run(3*time.Second, nil)
	if err != nil || d != ConsentTimedOut {
		t.Fatalf("brak odpowiedzi: %v err=%v", d, err)
	}
	waitUntil(t, "okno zgody znika po zabiciu podprocesu", func() bool { pid, _ := findWindow(consentTitle); return pid == 0 })
}

// Dowód mechanizmu, na którym stoi okno zgody: UIPI odrzuca wejście wstrzyknięte z procesu o NIŻSZEJ integralności do okna wyższej
// integralności, także kliknięcie myszą w przycisk MessageBox. Lokalnie nie ma jak zbudować okna o wysokiej integralności bez usługi SYSTEM,
// więc sprawdzamy ten sam mechanizm o jeden stopień niżej: okno tego procesu (średnia) i klikający proces o NISKIEJ integralności. Kontrola:
// to samo kliknięcie z procesu o średniej integralności zatwierdza okno, więc kursor stał w dobrym miejscu.
func TestLowIntegrityProcessCannotClickMediumIntegrityDialog(t *testing.T) {
	session := requireDesktop(t)
	title := "RMM test UIPI (nie klikaj)"
	ctl := make(chan uintptr, 1)
	go func() {
		tt, _ := windows.UTF16PtrFromString(title)
		tx, _ := windows.UTF16PtrFromString("Test automatyczny: okno zamknie się samo.")
		r, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(tx)), uintptr(unsafe.Pointer(tt)), uintptr(mbYesNoCancel|mbSetForeground|mbTopmost))
		ctl <- r
	}()
	waitUntil(t, "okno", func() bool { pid, _ := findWindow(title); return pid != 0 })
	time.Sleep(500 * time.Millisecond)
	_, wnd := findWindow(title)
	closeDialog := func() {
		procPostMessageW.Call(wnd, 0x0010, 0, 0) // WM_CLOSE: Anuluj
		select {
		case <-ctl:
		case <-time.After(3 * time.Second):
		}
	}
	btn, br, ok := nthButton(wnd, 1)
	if !ok {
		closeDialog()
		t.Skip("nie znaleziono przycisku okna")
	}
	restore, ok := hoverButton(btn, br)
	if !ok {
		closeDialog()
		t.Skip("okno przysłonięte (np. komputer zablokowany): test niemiarodajny")
	}
	defer restore()

	// Klikający proces o NISKIEJ integralności: ponownie uruchomiony plik testowy (token własny, ograniczony, integralność niska).
	self := ownPrimaryToken(t)
	restricted, err := wintoken.Restrict(self, false)
	if err != nil {
		closeDialog()
		t.Fatal(err)
	}
	defer restricted.Close()
	// Uchwyt z CreateRestrictedToken nie ma prawa TOKEN_ADJUST_DEFAULT (SetTokenInformation: „Access is denied”), więc integralność obniżamy na kopii.
	low, err := wintoken.ToPrimary(restricted)
	if err != nil {
		closeDialog()
		t.Fatal(err)
	}
	defer low.Close()
	if err := wintoken.SetIntegrity(low, wintoken.RIDLow); err != nil {
		closeDialog()
		t.Fatal(err)
	}
	dup, err := wintoken.ToPrimary(self)
	if err != nil {
		closeDialog()
		t.Fatal(err)
	}
	defer dup.Close()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	p, err := startWithToken(low, dup, false, session, os.Args[0], log, "-test.run=^TestLowIntegrityClickerChild$", "click")
	if err != nil {
		closeDialog()
		t.Skipf("nie udało się uruchomić klikającego procesu o niskiej integralności: %v", err)
	}
	pp := p.(*pipeProc)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pp.pid)
	if err != nil {
		closeDialog()
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 20_000); ev != windows.WAIT_OBJECT_0 {
		p.Kill()
		closeDialog()
		t.Fatal("klikający proces nie skończył się w czasie")
	}
	var code uint32
	_ = windows.GetExitCodeProcess(h, &code)
	if code != clickerExitCode {
		closeDialog()
		t.Skipf("klikający proces o niskiej integralności nie wykonał kliknięcia (kod %d): test niemiarodajny", code)
	}
	select {
	case r := <-ctl:
		t.Fatalf("kliknięcie z procesu o niskiej integralności zatwierdziło okno o wyższej integralności (odpowiedź %d): UIPI nie chroni", r)
	case <-time.After(1500 * time.Millisecond):
	}
	t.Log("kliknięcie z procesu o niskiej integralności zostało odrzucone przez UIPI")

	// Kontrola: to samo kliknięcie z procesu o tej samej integralności zatwierdza okno.
	clickHere()
	select {
	case r := <-ctl:
		if r != idYes {
			t.Fatalf("kontrolne kliknięcie dało %d zamiast IDYES", r)
		}
	case <-time.After(5 * time.Second):
		closeDialog()
		t.Skip("kontrolne kliknięcie nie zatwierdziło okna: test niemiarodajny")
	}
}

// clickerExitCode odróżnia „kliknąłem” od zwykłego zakończenia testu (go test kończy się kodem 0 także przy pominięciu).
const clickerExitCode = 42

// TestLowIntegrityClickerChild to tryb dziecka testu wyżej: wstrzykuje jedno kliknięcie w bieżącym położeniu kursora (ustawił je rodzic)
// i kończy się kodem clickerExitCode. Uruchomiony zwyczajnie (bez argumentu "click") nic nie robi.
func TestLowIntegrityClickerChild(t *testing.T) {
	if flag.NArg() != 1 || flag.Arg(0) != "click" {
		t.Skip("tryb pomocniczy dla TestLowIntegrityProcessCannotClickMediumIntegrityDialog")
	}
	clickHere()
	os.Exit(clickerExitCode)
}

func TestConsentStyleDefaultsToNoOnTopAndYesNo(t *testing.T) {
	const yesNo, defButton2, topmost, setForeground = 0x4, 0x100, 0x40000, 0x10000
	if consent.Style&yesNo == 0 || consent.Style&defButton2 == 0 || consent.Style&topmost == 0 || consent.Style&setForeground == 0 {
		t.Fatal("okno zgody ma mieć Tak/Nie z domyślnym „Nie”, na wierzchu i w pierwszym planie")
	}
}
