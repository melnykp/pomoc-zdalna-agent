//go:build windows

package update

import (
	"os"
	"strings"
	"testing"
)

// Test na prawdziwym, podpisanym przez producenta pliku z systemu. Odczyt jest tylko do odczytu.
func signedSystemFile(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft OneDrive\OneDrive.exe`,
		os.Getenv("LOCALAPPDATA") + `\Microsoft\OneDrive\OneDrive.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("brak znanego, podpisanego pliku na tym komputerze")
	return ""
}

func TestAuthenticodeReadsRealSignerSubject(t *testing.T) {
	file := signedSystemFile(t)
	subject, err := verifyAuthenticode(file)
	if err != nil {
		t.Skipf("plik %s nie ma osadzonego, ważnego podpisu: %v", file, err)
	}
	if !strings.Contains(subject, "CN=") {
		t.Fatalf("podmiot powinien mieć składnik CN: %q", subject)
	}
	t.Logf("%s podpisany przez: %s", file, subject)

	old := RequireAuthenticode
	RequireAuthenticode = "true"
	t.Cleanup(func() { RequireAuthenticode = old })
	if err := CheckSignature(file, subject); err != nil {
		t.Fatalf("zgodny podmiot powinien przejść: %v", err)
	}
	if err := CheckSignature(file, "CN=Ktoś Inny, C=PL"); err == nil {
		t.Fatal("niezgodny podmiot musi być odrzucony")
	}

	// Pin wkompilowany w plik: zgodny z podmiotem przechodzi, a obcy odrzuca nawet wtedy, gdy manifest się zgadza.
	oldPin := AuthenticodeSubjectPin
	t.Cleanup(func() { AuthenticodeSubjectPin = oldPin })
	AuthenticodeSubjectPin = subject
	if err := CheckSignature(file, subject); err != nil {
		t.Fatalf("zgodny pin powinien przejść: %v", err)
	}
	AuthenticodeSubjectPin = "CN=Intruz, O=Intruz, C=PL"
	if err := CheckSignature(file, subject); err == nil {
		t.Fatal("obcy pin musi odrzucić plik, nawet gdy podmiot zgadza się z manifestem")
	}
}

func TestAuthenticodeRejectsUnsignedFile(t *testing.T) {
	file := t.TempDir() + `\niepodpisany.exe`
	if err := os.WriteFile(file, []byte("MZ-to-nie-jest-program"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAuthenticode(file); err == nil {
		t.Fatal("plik bez podpisu nie może przejść WinVerifyTrust")
	}
}
