package identity

import (
	"path/filepath"
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
	if _, err := decode([]byte("to nie jest base64!")); err == nil {
		t.Fatal("śmieci przyjęte jako tożsamość")
	}
	if _, err := decode([]byte("AAAA")); err == nil {
		t.Fatal("zbyt krótki seed przyjęty")
	}
}
