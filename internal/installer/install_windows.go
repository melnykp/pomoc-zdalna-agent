//go:build windows

package installer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
)

const (
	serviceDisplay      = config.ProductName + " (agent)"
	serviceDescription  = "Zdalna pomoc techniczna: raportuje stan komputera i wykonuje polecenia inżyniera."
	watchdogDisplay     = config.ProductName + " (nadzorca)"
	watchdogDescription = "Nadzoruje agenta zdalnej pomocy: aktualizuje go i przywraca poprzednią wersję, gdy nowa nie działa."
	detachedProcess     = 0x00000008
)

// ProgramFilesDir to katalog programu: %ProgramFiles%\<Nazwa>.
func ProgramFilesDir() string {
	// Z systemu (SHGetKnownFolderPath), nie ze zmiennej środowiskowej, którą może przestawić zwykły użytkownik.
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil || base == "" {
		base = os.Getenv("ProgramFiles")
	}
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, config.ProductDirName)
}

// InstalledExe to docelowa ścieżka pliku agenta.
func InstalledExe() string { return filepath.Join(ProgramFilesDir(), "agent.exe") }

// InstalledWatchdogExe to docelowa ścieżka pliku nadzorcy.
func InstalledWatchdogExe() string { return filepath.Join(ProgramFilesDir(), "watchdog.exe") }

// Install wykonuje pełną instalację i wymaga uprawnień administratora (podnosi je wywołujący):
// zabezpiecza katalog danych, rejestruje urządzenie, kopiuje agenta do Program Files i uruchamia usługę.
func Install(ctx context.Context, p Params) (Result, error) {
	if !svc.IsAdmin() {
		return Result{}, errors.New("instalacja wymaga uprawnień administratora")
	}
	// Własny plik otwieramy od razu i trzymamy z blokadą zapisu: po zgodzie UAC nikt nie podmieni go przed kopiowaniem.
	selfPath, err := os.Executable()
	if err != nil {
		return Result{}, err
	}
	self, err := svc.OpenLocked(selfPath)
	if err != nil {
		return Result{}, fmt.Errorf("otwarcie własnego pliku: %w", err)
	}
	defer self.Close()

	dataDir := config.DataDir()
	// Katalog danych, który ktoś utworzył przed instalacją (zwykły użytkownik może tworzyć podkatalogi w ProgramData),
	// nie jest zaufany: odkładamy go na bok i zakładamy nowy z właścicielem Administratorzy.
	if err := svc.PrepareDataDir(dataDir); err != nil {
		return Result{}, fmt.Errorf("przygotowanie katalogu danych: %w", err)
	}
	if err := svc.SecureDir(dataDir); err != nil {
		return Result{}, fmt.Errorf("zabezpieczenie katalogu danych: %w", err)
	}
	p.DataDir = dataDir

	res, err := Enroll(ctx, p)
	if err != nil {
		return res, err
	}

	// Najpierw nadzorca, bo zatrzymany agent byłby przez niego od razu uruchamiany z powrotem.
	if err := svc.Stop(svc.WatchdogServiceName); err != nil {
		return res, fmt.Errorf("zatrzymanie nadzorcy: %w", err)
	}
	if err := svc.Stop(svc.ServiceName); err != nil {
		return res, fmt.Errorf("zatrzymanie poprzedniej wersji: %w", err)
	}
	agentExe, watchdogExe := InstalledExe(), InstalledWatchdogExe()
	// Agent i nadzorca to ten sam plik w dwóch kopiach: nadzorca zostaje przy wersji, z którą go zainstalowano,
	// więc wadliwa aktualizacja agenta nie psuje mechanizmu rollbacku.
	for _, target := range []string{agentExe, watchdogExe} {
		if err := copySelf(self, selfPath, target); err != nil {
			return res, fmt.Errorf("kopiowanie programu: %w", err)
		}
	}
	if err := svc.Install(svc.ServiceName, serviceDisplay, serviceDescription, agentExe, "service"); err != nil {
		return res, err
	}
	if err := svc.Install(svc.WatchdogServiceName, watchdogDisplay, watchdogDescription, watchdogExe, "watchdog-service"); err != nil {
		return res, err
	}
	if err := svc.Start(svc.ServiceName); err != nil {
		return res, err
	}
	if err := svc.Start(svc.WatchdogServiceName); err != nil {
		return res, err
	}
	return res, nil
}

// copySelf kopiuje program z uchwytu otwartego na początku instalacji (src), a nie z ponownie otwartej ścieżki.
func copySelf(src *os.File, selfPath, target string) error {
	if same, _ := sameFile(selfPath, target); same {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tmp := target + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(target)
	return os.Rename(tmp, target)
}

func sameFile(a, b string) (bool, error) {
	ai, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(ai, bi), nil
}

// removable pilnuje, żeby czyszczenie dotknęło wyłącznie katalogów produktu, także gdy ścieżki
// przyszły ze zmiennych środowiskowych.
func removable(dir string) bool {
	clean := filepath.Clean(dir)
	return strings.EqualFold(filepath.Base(clean), config.ProductDirName) && len(clean) > len(filepath.VolumeName(clean))+2
}

// Retire usuwa agenta z komputera na polecenie serwera (device.retire): oznacza usługę do usunięcia,
// zleca odłączonemu procesowi skasowanie plików po zatrzymaniu usługi i zatrzymuje usługę.
func Retire() error {
	// Nadzorca pierwszy: żywy uruchamiałby agenta z powrotem po jego zatrzymaniu.
	if err := svc.Delete(svc.WatchdogServiceName); err != nil {
		return err
	}
	if err := svc.Delete(svc.ServiceName); err != nil {
		return err
	}
	if err := scheduleCleanup(); err != nil {
		return err
	}
	if err := svc.Stop(svc.WatchdogServiceName); err != nil {
		return err
	}
	return svc.Stop(svc.ServiceName)
}

// Uninstall robi to samo na polecenie administratora lokalnie (agent uninstall).
func Uninstall() error { return Retire() }

func scheduleCleanup() error {
	dirs := []string{ProgramFilesDir(), config.DataDir()}
	var cmds []string
	for _, d := range dirs {
		if !removable(d) {
			return fmt.Errorf("odmowa usunięcia nietypowej ścieżki %q", d)
		}
		cmds = append(cmds, fmt.Sprintf(`rmdir /s /q "%s"`, d))
	}
	// Opóźnienie daje usłudze czas na zatrzymanie, bo pliki działającego programu są zablokowane.
	script := "timeout /t 20 /nobreak >nul & " + strings.Join(cmds, " & ")
	c := exec.Command("cmd.exe", "/c", script)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP}
	return c.Start()
}
