// Package identity zarządza tożsamością urządzenia: parą kluczy Ed25519 generowaną
// przy pierwszym starcie. Serwer zna wyłącznie klucz publiczny (docs/ARCHITECTURE.md).
//
// TODO przed pierwszym wdrożeniem u klienta: klucz prywatny szyfrowany DPAPI w zakresie
// maszyny (billgraziano/dpapi), katalog z ACL tylko dla SYSTEM i Administratorów.
// W szkielecie plik ma uprawnienia 0600, co na Windows nie jest realną ochroną.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Identity to para kluczy urządzenia.
type Identity struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// LoadOrCreate wczytuje tożsamość z path albo tworzy nową, gdy pliku nie ma.
// Drugi wynik mówi, czy tożsamość została właśnie utworzona.
func LoadOrCreate(path string) (*Identity, bool, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		id, err := decode(raw)
		return id, false, err
	case errors.Is(err, os.ErrNotExist):
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(path, encode(priv), 0o600); err != nil {
			return nil, false, err
		}
		return &Identity{Public: pub, Private: priv}, true, nil
	default:
		return nil, false, err
	}
}

func encode(priv ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
}

func decode(raw []byte) (*Identity, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("identity: zły format pliku: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: zła długość seeda: %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{Public: priv.Public().(ed25519.PublicKey), Private: priv}, nil
}

// PublicBase64 zwraca klucz publiczny w postaci wysyłanej przy rejestracji.
func (i *Identity) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(i.Public)
}
