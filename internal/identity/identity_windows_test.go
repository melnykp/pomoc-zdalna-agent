//go:build windows

package identity

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewIdentityIsEncryptedWithDPAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")
	id, _, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, sealedPrefix) {
		t.Fatalf("nowy plik powinien być zaszyfrowany DPAPI, jest: %.20q", text)
	}
	if strings.Contains(text, base64.StdEncoding.EncodeToString(id.Private.Seed())) {
		t.Fatal("plik zawiera klucz prywatny otwartym tekstem")
	}
}

func TestSealedFileRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")
	if _, _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	body, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), sealedPrefix))

	flipped := append([]byte(nil), body...)
	flipped[len(flipped)/2] ^= 0xff
	if err := os.WriteFile(path, []byte(sealedPrefix+base64.StdEncoding.EncodeToString(flipped)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Fatal("uszkodzony blok DPAPI został przyjęty")
	}

	if err := os.WriteFile(path, []byte(sealedPrefix+base64.StdEncoding.EncodeToString(body[:10])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreate(path); err == nil {
		t.Fatal("ucięty blok DPAPI został przyjęty")
	}
}
