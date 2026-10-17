//go:build windows

package svc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	winsvc "golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// IsWindowsService mówi, czy proces został uruchomiony przez menedżera usług.
func IsWindowsService() bool {
	ok, err := winsvc.IsWindowsService()
	return err == nil && ok
}

type handler struct{ r Runner }

// Execute to pętla usługi: uruchamia Runner i obsługuje polecenia stop oraz shutdown z SCM.
func (h *handler) Execute(_ []string, req <-chan winsvc.ChangeRequest, status chan<- winsvc.Status) (bool, uint32) {
	const accepted = winsvc.AcceptStop | winsvc.AcceptShutdown
	status <- winsvc.Status{State: winsvc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.r.Run(ctx) }()
	status <- winsvc.Status{State: winsvc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// Runner zakończył się sam (np. polecenie restartu): kod błędu każe SCM uruchomić usługę ponownie.
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case winsvc.Interrogate:
				status <- c.CurrentStatus
			case winsvc.Stop, winsvc.Shutdown:
				status <- winsvc.Status{State: winsvc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// RunService oddaje sterowanie menedżerowi usług do czasu zatrzymania usługi.
func RunService(name string, r Runner) error {
	return winsvc.Run(name, &handler{r: r})
}

// IsAdmin mówi, czy proces ma podniesiony token (uruchomiony jako administrator).
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Elevate uruchamia exe z args przez ShellExecute „runas”, co wyświetla okno UAC.
func Elevate(exe string, args []string) error {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	dir, _ := windows.UTF16PtrFromString(cwd)
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_NORMAL)
}

// Install rejestruje usługę (start automatyczny, konto LocalSystem) z akcjami odzyskiwania:
// restart po 5 s, 5 s i 30 s. Jeśli usługa istnieje, aktualizuje tylko ścieżkę pliku.
func Install(name, display, description, exePath string, args ...string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("svc: połączenie z menedżerem usług: %w", err)
	}
	defer m.Disconnect()

	cfg := mgr.Config{
		DisplayName:  display,
		Description:  description,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}
	s, err := m.OpenService(name)
	if err == nil {
		defer s.Close()
		cur, qerr := s.Config()
		if qerr != nil {
			return qerr
		}
		cur.BinaryPathName = quoteCommand(exePath, args)
		cur.DisplayName = display
		cur.Description = description
		cur.StartType = mgr.StartAutomatic
		if err := s.UpdateConfig(cur); err != nil {
			return fmt.Errorf("svc: aktualizacja usługi: %w", err)
		}
	} else {
		s, err = m.CreateService(name, exePath, cfg, args...)
		if err != nil {
			return fmt.Errorf("svc: tworzenie usługi: %w", err)
		}
		defer s.Close()
	}
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 24*3600); err != nil {
		return fmt.Errorf("svc: akcje odzyskiwania: %w", err)
	}
	return nil
}

func quoteCommand(exe string, args []string) string {
	parts := []string{windows.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, windows.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// Start uruchamia usługę i czeka do 30 s na stan Running.
func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("svc: start usługi: %w", err)
	}
	return waitState(s, winsvc.Running)
}

// Stop zatrzymuje usługę i czeka do 30 s; brak usługi albo jej zatrzymanie nie są błędem.
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	if _, err := s.Control(winsvc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("svc: stop usługi: %w", err)
	}
	return waitState(s, winsvc.Stopped)
}

func waitState(s *mgr.Service, want winsvc.State) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("svc: usługa nie osiągnęła oczekiwanego stanu w 30 s")
}

// Uninstall zatrzymuje i usuwa usługę. Brak usługi nie jest błędem.
func Uninstall(name string) error {
	if err := Stop(name); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	return s.Delete()
}

// Exists mówi, czy usługa jest zarejestrowana.
func Exists(name string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// SecureDir ogranicza katalog do SYSTEM i Administratorów (bez dziedziczenia). Klucz urządzenia i konfiguracja
// nie powinny być czytelne dla zwykłych użytkowników komputera.
func SecureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	// D: DACL chroniony (P) z automatycznym dziedziczeniem do podobiektów (AI); pełna kontrola dla SY i BA.
	sd, err := windows.SecurityDescriptorFromString("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Message pokazuje okno komunikatu. Gdy isError, z ikoną błędu.
func Message(title, text string, isError bool) {
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION | windows.MB_SETFOREGROUND)
	if isError {
		flags = uint32(windows.MB_OK | windows.MB_ICONERROR | windows.MB_SETFOREGROUND)
	}
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString(title)
	_, _ = windows.MessageBox(0, t, c, flags)
}

// Delete oznacza usługę do usunięcia bez zatrzymywania; zniknie po zatrzymaniu. Brak usługi nie jest błędem.
func Delete(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil
	}
	defer s.Close()
	return s.Delete()
}

// IsRunning mówi, czy usługa jest w stanie Running (albo uruchamia się).
func IsRunning(name string) bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && (st.State == winsvc.Running || st.State == winsvc.StartPending)
}

// IsWindowsServiceCapable mówi, że na tej platformie istnieje menedżer usług.
func IsWindowsServiceCapable() bool { return true }

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// AttachParentConsole podłącza plik zbudowany jako aplikacja okienkowa (-H=windowsgui) do konsoli procesu, który go
// uruchomił, żeby wypisy z wiersza poleceń były widoczne. Przy uruchomieniu z Eksploratora albo przez menedżer
// usług konsoli nie ma i nic się nie dzieje. Gdy wyjście jest już przekierowane (potok, plik), zostaje bez zmian.
func AttachParentConsole() {
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != windows.InvalidHandle {
		return
	}
	const attachParentProcess = ^uintptr(0) // ATTACH_PARENT_PROCESS = (DWORD)-1
	if r, _, _ := procAttachConsole.Call(attachParentProcess); r == 0 {
		return
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = out, out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
}
