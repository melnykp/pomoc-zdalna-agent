//go:build windows

package remote

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hideWindow uruchamia proces potomny bez okna konsoli.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// DefaultExe to domyślna ścieżka rustdesk.exe po cichej instalacji (Program Files z systemu, nie ze zmiennej środowiskowej).
func DefaultExe() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil || base == "" {
		base = "C:/Program Files"
	}
	return filepath.Join(base, "RustDesk", "rustdesk.exe")
}

// processCommandLines zwraca linie poleceń wszystkich procesów o podanej nazwie pliku (bez wielkości liter).
func processCommandLines(image string) ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var lines []string
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if !strings.EqualFold(windows.UTF16ToString(pe.ExeFile[:]), image) {
			continue
		}
		if cl, cerr := commandLineOf(pe.ProcessID); cerr == nil {
			lines = append(lines, cl)
		}
	}
	return lines, nil
}

// processCommandLineInformation to klasa NtQueryInformationProcess zwracająca linię poleceń (Windows 8.1 i nowsze).
const processCommandLineInformation = 60

func commandLineOf(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var need uint32
	// Pierwsze wywołanie z zerowym buforem zwraca wymagany rozmiar (status „zły rozmiar”); błąd jest oczekiwany.
	_ = windows.NtQueryInformationProcess(h, processCommandLineInformation, nil, 0, &need)
	if need == 0 || need > 1<<20 {
		return "", windows.ERROR_INSUFFICIENT_BUFFER
	}
	buf := make([]byte, need)
	if err := windows.NtQueryInformationProcess(h, processCommandLineInformation, unsafe.Pointer(&buf[0]), need, &need); err != nil {
		return "", err
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return us.String(), nil
}
