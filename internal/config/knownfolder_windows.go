//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows"
)

// programDataDir zwraca katalog ProgramData z systemu (SHGetKnownFolderPath), a nie ze zmiennej środowiskowej. Zmienną
// środowiskową może przestawić zwykły użytkownik (HKCU\Environment), a podniesiony instalator dziedziczy ją po nim, więc
// dane usługi działającej jako SYSTEM mogłyby trafić do katalogu pod kontrolą użytkownika.
func programDataDir() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT); err == nil && p != "" {
		return p
	}
	if env := os.Getenv("ProgramData"); env != "" {
		return env
	}
	return `C:\ProgramData`
}
