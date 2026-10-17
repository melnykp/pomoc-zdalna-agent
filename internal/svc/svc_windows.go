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
	// Właścicielem katalogu zostają Administratorzy: właściciel ma domyślnie prawo zmiany uprawnień, a nie chcemy go
	// zostawiać nikomu spoza zaufanych kont.
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil)
	if err != nil {
		// Nie każdy token pozwala przypisać właściciela. Katalog założony przez podniesiony proces ma go już dobrego, więc
		// ustawiamy samo DACL, a na końcu sprawdzamy, że właściciel jest zaufany.
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return err
		}
	}
	if ok, err := DirTrusted(path); err != nil || !ok {
		return fmt.Errorf("katalog %s nie ma zaufanego właściciela (SYSTEM, Administratorzy): %v", path, err)
	}
	return nil
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

// trustedOwners to właściciele, którym wolno należeć do katalogu danych: SYSTEM, Administratorzy i TrustedInstaller.
func trustedOwners() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	ti, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return nil, err
	}
	return append(out, ti), nil
}

// DirTrusted mówi, czy katalog jest zwykłym katalogiem (nie dowiązaniem ani junctionem) należącym do SYSTEM,
// Administratorów albo TrustedInstaller. Katalog w ProgramData, który utworzył zwykły użytkownik, zaufany nie jest:
// jego właściciel ma zawsze prawo zmiany uprawnień, więc po instalacji mógłby odzyskać dostęp do klucza urządzenia
// i plików stanu watchdoga (konto SYSTEM).
func DirTrusted(path string) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return false, err
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, nil
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	owners, err := trustedOwners()
	if err != nil {
		return false, err
	}
	for _, o := range owners {
		if owner.Equals(o) {
			return true, nil
		}
	}
	return false, nil
}

// PrepareDataDir przygotowuje katalog danych do instalacji. Brak katalogu: tworzy go. Katalog zaufany: zostaje.
// Katalog, który ktoś utworzył wcześniej (cudzy właściciel, dowiązanie), jest odkładany na bok pod inną nazwą i
// zakładany od nowa, a gdy się nie da (otwarte uchwyty), instalacja jest przerywana.
func PrepareDataDir(dir string) error {
	_, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if ok, err := DirTrusted(dir); err == nil && ok {
		return nil
	}
	aside := dir + ".niezaufany-" + time.Now().Format("20060102-150405")
	if err := os.Rename(dir, aside); err != nil {
		return fmt.Errorf("katalog danych %s utworzył ktoś inny i nie da się go odłożyć: %w", dir, err)
	}
	return os.MkdirAll(dir, 0o700)
}

// OpenLocked otwiera plik do odczytu z wyłącznym prawem do zapisu i usunięcia dla nas (inni mogą tylko czytać). Instalator
// otwiera tak własny plik na początku, żeby po zgodzie UAC nikt nie podmienił go przed kopiowaniem do Program Files.
func OpenLocked(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
