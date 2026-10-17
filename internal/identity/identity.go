// Package identity zarządza tożsamością urządzenia: parą kluczy Ed25519 generowaną
// przy pierwszym starcie. Serwer zna wyłącznie klucz publiczny (docs/ARCHITECTURE.md).
//
// W Windows klucz prywatny jest szyfrowany DPAPI w zakresie maszyny (plik z przedrostkiem "PMZ1:"), więc kopia pliku
// zabrana z dysku albo z kopii zapasowej nie działa na innym komputerze. Katalog danych ma dodatkowo ACL tylko dla
// SYSTEM i Administratorów (svc.SecureDir), bo zakres maszyny nie chroni przed lokalnym użytkownikiem z dostępem do pliku.
// Stary plik ze zwykłym tekstem jest przy pierwszym odczycie przepisywany na zaszyfrowany. Poza Windows plik zostaje
// zwykłym tekstem z uprawnieniami 0600 (tryb rozwojowy).
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

// sealedPrefix oznacza plik z kluczem zaszyfrowanym DPAPI (reszta to base64 bloku DPAPI).
const sealedPrefix = "PMZ1:"

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
		id, wasPlain, err := decode(raw)
		if err != nil {
			return nil, false, err
		}
		if wasPlain {
			// Stary plik ze zwykłym tekstem: przepisujemy na zaszyfrowany. Gdy się nie uda, tożsamość nadal działa
			// (plik zostaje jak był), a próba powtórzy się przy następnym starcie.
			if sealed, serr := encode(id.Private); serr == nil && !isPlain(sealed) {
				_ = writeAtomic(path, sealed)
			}
		}
		return id, false, nil
	case errors.Is(err, os.ErrNotExist):
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, err
		}
		content, err := encode(priv)
		if err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, false, err
		}
		if err := writeAtomic(path, content); err != nil {
			return nil, false, err
		}
		return &Identity{Public: pub, Private: priv}, true, nil
	default:
		return nil, false, err
	}
}

// encode składa zawartość pliku: zaszyfrowaną DPAPI w Windows, zwykły tekst poza nim.
func encode(priv ed25519.PrivateKey) ([]byte, error) {
	seed := priv.Seed()
	blobBytes, supported, err := protect(seed)
	if err != nil {
		return nil, err
	}
	if !supported {
		return []byte(base64.StdEncoding.EncodeToString(seed) + "\n"), nil
	}
	return []byte(sealedPrefix + base64.StdEncoding.EncodeToString(blobBytes) + "\n"), nil
}

func isPlain(content []byte) bool {
	return !strings.HasPrefix(strings.TrimSpace(string(content)), sealedPrefix)
}

// decode odczytuje klucz z zawartości pliku. Drugi wynik mówi, że plik był zwykłym tekstem (do przepisania).
func decode(raw []byte) (*Identity, bool, error) {
	text := strings.TrimSpace(string(raw))
	plain := true
	var seed []byte
	if strings.HasPrefix(text, sealedPrefix) {
		plain = false
		sealed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, sealedPrefix))
		if err != nil {
			return nil, false, fmt.Errorf("identity: zły format pliku: %w", err)
		}
		if seed, err = unprotect(sealed); err != nil {
			return nil, false, err
		}
	} else {
		var err error
		if seed, err = base64.StdEncoding.DecodeString(text); err != nil {
			return nil, false, fmt.Errorf("identity: zły format pliku: %w", err)
		}
	}
	if len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("identity: zła długość seeda: %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{Public: priv.Public().(ed25519.PublicKey), Private: priv}, plain, nil
}

// writeAtomic zapisuje plik przez plik tymczasowy i zmianę nazwy, żeby przerwany zapis nie zostawił uciętego klucza.
func writeAtomic(path string, content []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// PublicBase64 zwraca klucz publiczny w postaci wysyłanej przy rejestracji.
func (i *Identity) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(i.Public)
}
