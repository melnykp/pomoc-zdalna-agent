//go:build windows

package svc

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// SecureDir odbiera dostęp zwykłym użytkownikom, więc test uruchamiamy tylko jako administrator:
// inaczej sprzątanie katalogu tymczasowego byłoby niemożliwe.
func TestSecureDirProtectsDACL(t *testing.T) {
	if !IsAdmin() {
		t.Skip("wymaga uprawnień administratora")
	}
	dir := filepath.Join(t.TempDir(), "dane")
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("administrator powinien móc pisać w zabezpieczonym katalogu: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("DACL powinien być chroniony przed dziedziczeniem")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("oczekiwano dwóch wpisów (SYSTEM, Administratorzy): %v ace=%v", err, dacl)
	}
}

func TestIsAdminDoesNotPanic(t *testing.T) {
	t.Logf("administrator: %v", IsAdmin())
}
