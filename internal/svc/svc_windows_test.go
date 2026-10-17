//go:build windows

package svc

import (
	"os"
	"os/exec"
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

func TestDirTrustedAcceptsSystemDirectoriesAndRejectsUserOnes(t *testing.T) {
	if ok, err := DirTrusted(os.Getenv("SystemRoot")); err != nil || !ok {
		t.Fatalf("katalog Windows (TrustedInstaller) powinien być zaufany: ok=%v err=%v", ok, err)
	}
	if IsAdmin() {
		t.Skip("testy właściciela zwykłego użytkownika wymagają procesu bez podniesionych uprawnień")
	}
	dir := t.TempDir()
	if ok, err := DirTrusted(dir); err != nil || ok {
		t.Fatalf("katalog zwykłego użytkownika nie może być zaufany: ok=%v err=%v", ok, err)
	}
	file := filepath.Join(dir, "plik.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := DirTrusted(file); ok {
		t.Fatal("zwykły plik nie jest katalogiem zaufanym")
	}
}

func TestDirTrustedRejectsJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(os.Getenv("SystemRoot"), "System32")
	link := filepath.Join(base, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("nie da się utworzyć junctionu: %v %s", err, out)
	}
	// Cel jest zaufany (System32), ale samo dowiązanie nie może być uznane za katalog danych.
	if ok, err := DirTrusted(link); err != nil || ok {
		t.Fatalf("junction nie może być zaufany: ok=%v err=%v", ok, err)
	}
}

func TestPrepareDataDirMovesUntrustedDirectoryAside(t *testing.T) {
	if IsAdmin() {
		t.Skip("wymaga procesu bez podniesionych uprawnień (katalog zwykłego użytkownika jest wtedy niezaufany)")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "dane")
	if err := os.MkdirAll(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "state", "update-request.json")
	if err := os.WriteFile(planted, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := PrepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("nowy katalog danych ma być pusty, jest w nim %d wpisów", len(entries))
	}
	if _, err := os.Stat(planted); err == nil {
		t.Fatal("podrzucony plik został w katalogu danych")
	}
	asides, _ := filepath.Glob(dir + ".niezaufany-*")
	if len(asides) != 1 {
		t.Fatalf("stary katalog powinien zostać odłożony na bok, znaleziono: %v", asides)
	}
}

func TestPrepareDataDirCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nowy", "dane")
	if err := PrepareDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("katalog powinien powstać: %v", err)
	}
}

func TestOpenLockedBlocksWritesAndDeletes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plik.exe")
	if err := os.WriteFile(path, []byte("oryginal"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenLocked(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.WriteFile(path, []byte("podmiana"), 0o600); err == nil {
		t.Fatal("zapis do zablokowanego pliku powinien się nie udać")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("usunięcie zablokowanego pliku powinno się nie udać")
	}
	got := make([]byte, 8)
	if n, _ := f.Read(got); string(got[:n]) != "oryginal" {
		t.Fatalf("zawartość po próbie podmiany: %q", got[:n])
	}
}
