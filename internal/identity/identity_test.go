package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")

	first, created, err := LoadOrCreate(path)
	if err != nil || !created {
		t.Fatalf("pierwsze wywołanie powinno utworzyć tożsamość: created=%v err=%v", created, err)
	}
	second, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("drugie wywołanie powinno wczytać tożsamość: created=%v err=%v", created, err)
	}
	if first.PublicBase64() != second.PublicBase64() {
		t.Fatal("klucz publiczny zmienił się między uruchomieniami")
	}
	if string(first.Private) != string(second.Private) {
		t.Fatal("klucz prywatny zmienił się między uruchomieniami")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, _, err := decode([]byte("to nie jest base64!")); err == nil {
		t.Fatal("śmieci przyjęte jako tożsamość")
	}
	if _, _, err := decode([]byte("AAAA")); err == nil {
		t.Fatal("zbyt krótki seed przyjęty")
	}
	if _, _, err := decode([]byte(sealedPrefix + "to nie jest base64!")); err == nil {
		t.Fatal("śmieci po przedrostku przyjęte jako tożsamość")
	}
}

// Stary plik ze zwykłym tekstem (sprzed szyfrowania) musi się nadal wczytywać tym samym kluczem, a w Windows
// zostać przepisany na zaszyfrowany. Poza Windows zostaje zwykłym tekstem.
func TestLegacyPlaintextFileIsReadAndUpgraded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	plain := base64.StdEncoding.EncodeToString(seed) + "\n"
	if err := os.WriteFile(path, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed)

	id, created, err := LoadOrCreate(path)
	if err != nil || created {
		t.Fatalf("stary plik powinien się wczytać: created=%v err=%v", created, err)
	}
	if string(id.Private) != string(want) {
		t.Fatal("po wczytaniu starego pliku klucz się zmienił")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed := strings.HasPrefix(string(after), sealedPrefix)
	if runtime.GOOS == "windows" && !sealed {
		t.Fatal("w Windows stary plik powinien zostać przepisany na zaszyfrowany")
	}
	if runtime.GOOS != "windows" && sealed {
		t.Fatal("poza Windows plik nie powinien być szyfrowany")
	}
	if sealed && strings.Contains(string(after), base64.StdEncoding.EncodeToString(seed)) {
		t.Fatal("zaszyfrowany plik zawiera klucz otwartym tekstem")
	}

	// Drugi odczyt (już po przepisaniu) daje ten sam klucz.
	again, _, err := LoadOrCreate(path)
	if err != nil || string(again.Private) != string(want) {
		t.Fatalf("odczyt po przepisaniu: err=%v", err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("po zapisie został plik tymczasowy")
	}
}
