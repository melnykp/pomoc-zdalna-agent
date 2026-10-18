//go:build windows

// Package consent pokazuje okno zgody na podniesienie uprawnień pomocnika (wydanie 0.4.3). Działa wyłącznie jako krótko żyjący podproces
// desktop-helper.exe uruchamiany przez usługę agenta z tokenem o WYSOKIEJ integralności w sesji zalogowanego użytkownika
// (desktop-helper.exe consent <tytuł-base64> <treść-base64>).
//
// Dlaczego osobny proces o wysokiej integralności, a nie MessageBox w pomocniku ani WTSSendMessage: pomocnik na poziomie „user” ma średnią
// integralność i potrafi wstrzykiwać wejście (to jego zadanie), więc okno należące do niego albo do jakiegokolwiek procesu średniej integralności
// mógłby zatwierdzić sam: inżynier zatwierdziłby własną prośbę. UIPI odrzuca wejście wstrzykiwane z niższej integralności do okna procesu o wysokiej
// integralności (to samo UIPI, które zablokowało sterowanie oknem „Administrator: PowerShell”). Sprawdzone empirycznie 18.10.2026: okno z WTSSendMessage
// (csrss, system) NIE jest chronione, bo wstrzyknięte kliknięcie z procesu o średniej integralności zatwierdziło je.
//
// To bariera użyteczności i zgoda użytkownika w obrębie jednego pulpitu, a NIE twarda granica bezpieczeństwa: UIPI nią nie jest, a okno można zasłonić
// innym oknem na tym samym pulpicie. Osobny pulpit zgody (CreateDesktop z własnym DACL i SwitchDesktop) to dług na etap 1b (ADR-0009).
package consent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
)

var procMessageBoxW = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

// Style okna (jak w MessageBox) i odpowiedzi.
const (
	mbYesNo         = 0x00000004
	mbIconWarning   = 0x00000030
	mbDefButton2    = 0x00000100 // domyślnie „Nie”
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000

	idYes = 6
)

// Style to styl okna zgody: Tak/Nie, ostrzeżenie, domyślnie „Nie”, na wierzchu, w pierwszym planie.
const Style = mbYesNo | mbIconWarning | mbDefButton2 | mbSetForeground | mbTopmost

// show pokazuje okno i czeka na odpowiedź; zwraca true tylko dla „Tak”.
func show(title, text string) (bool, error) {
	t, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return false, err
	}
	m, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return false, err
	}
	r, _, e := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), uintptr(Style))
	if r == 0 {
		return false, fmt.Errorf("MessageBox: %w", e)
	}
	return r == idYes, nil
}

// Run dekoduje tytuł i treść (base64, żeby nie męczyć się z cudzysłowami w wierszu poleceń), pokazuje okno i zapisuje decyzję na out jako
// komunikat ipc (consent: allow | deny). Każdy błąd to odmowa. Zwraca błąd tylko do zapisania w dzienniku.
func Run(out io.Writer, titleB64, textB64 string) error {
	return RunWith(out, titleB64, textB64, show)
}

// RunWith to Run z podstawialnym oknem (testy).
func RunWith(out io.Writer, titleB64, textB64 string, ask func(title, text string) (bool, error)) error {
	answer := func(allow bool) error {
		state := ipc.ConsentDeny
		if allow {
			state = ipc.ConsentAllow
		}
		return ipc.WriteLine(out, ipc.DesktopMsg{Kind: ipc.DesktopConsent, State: state})
	}
	title, err1 := base64.StdEncoding.DecodeString(titleB64)
	text, err2 := base64.StdEncoding.DecodeString(textB64)
	if err1 != nil || err2 != nil {
		_ = answer(false)
		return errors.New("zły tytuł albo treść okna zgody")
	}
	allow, err := ask(string(title), string(text))
	if err != nil {
		_ = answer(false)
		return err
	}
	return answer(allow)
}
