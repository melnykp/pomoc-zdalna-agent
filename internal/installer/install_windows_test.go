//go:build windows

package installer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemovableOnlyAcceptsProductDirectories(t *testing.T) {
	good := []string{`C:\Program Files\Piotr Melnyk IT - POMOC Zdalna`, `C:\ProgramData\Piotr Melnyk IT - POMOC Zdalna`, `D:\Dane\piotr melnyk it - pomoc zdalna`}
	bad := []string{`C:\`, `C:\Windows`, `C:\Program Files`, `C:\Users\klient`, `C:\Piotr Melnyk IT - POMOC Zdalna2`, ``, `.`, `C:\Program Files\Piotr Melnyk IT - POMOC Zdalna\..`}
	for _, d := range good {
		if !removable(d) {
			t.Errorf("%q powinno być do usunięcia", d)
		}
	}
	for _, d := range bad {
		if removable(d) {
			t.Errorf("%q nie może być do usunięcia", d)
		}
	}
}

// Prawdziwy strumień NTFS: tak przeglądarka oznacza pobrany plik (adres pobrania zawiera token zaproszenia).
func TestTokenFromRealZoneIdentifierStream(t *testing.T) {
	const token = "k3Jx9QpL0vT2mN8sB4wZ7cH1yD6fG5aR-eU_oI3nM9q"
	exe := filepath.Join(t.TempDir(), "Piotr-Melnyk-IT-POMOC-Zdalna-Setup.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := tokenFromZoneIdentifierFile(exe); ok {
		t.Fatal("plik bez strumienia nie powinien dać tokenu")
	}
	content := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://agent.example.pl/i/" + token + "\r\nHostUrl=https://agent.example.pl/i/" + token + "/Piotr-Melnyk-IT-POMOC-Zdalna-Setup.exe\r\n"
	if err := os.WriteFile(exe+":Zone.Identifier", []byte(content), 0o600); err != nil {
		t.Skipf("system plików bez strumieni alternatywnych: %v", err)
	}
	got, ok := tokenFromZoneIdentifierFile(exe)
	if !ok || got != token {
		t.Fatalf("ok=%v token=%q", ok, got)
	}
}
