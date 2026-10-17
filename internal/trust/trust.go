// Package trust wybiera klucze publiczne serwera, którym agent ufa przy handshake
// (docs/ARCHITECTURE.md).
//
// Produkcyjny build ma klucze wkompilowane przez -ldflags "-X github.com/melnykp/pomoc-zdalna-agent/internal/trust.Compiled=id=base64,id2=base64".
// Wtedy klucze z config.json są ignorowane: przejęcie pliku konfiguracji albo odpowiedzi rejestracji
// nie pozwala podstawić obcego serwera. Build rozwojowy bez wkompilowanych kluczy ufa tym zapisanym
// przy rejestracji (odpowiedź przyszła kanałem TLS do adresu z zaproszenia).
package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
)

// Compiled to lista „id=base64” rozdzielona przecinkami, wstrzykiwana przy budowaniu.
var Compiled string

// Pinned mówi, czy build ma wkompilowane klucze.
func Pinned() bool { return strings.TrimSpace(Compiled) != "" }

// Parse zamienia klucz w base64 na klucz Ed25519.
func Parse(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("trust: zły base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trust: klucz ma %d bajtów, powinien mieć %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Keys zwraca zaufane klucze serwera: wkompilowane, a gdy ich nie ma, zapisane w konfiguracji.
func Keys(cfgKeys []config.ServerKey) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	if Pinned() {
		for _, part := range strings.Split(Compiled, ",") {
			_, b64, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				return nil, fmt.Errorf("trust: wkompilowany klucz bez formatu id=base64: %q", part)
			}
			k, err := Parse(b64)
			if err != nil {
				return nil, err
			}
			out = append(out, k)
		}
	} else {
		for _, k := range cfgKeys {
			pk, err := Parse(k.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("klucz %q: %w", k.KeyID, err)
			}
			out = append(out, pk)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("trust: brak zaufanych kluczy serwera (zarejestruj agenta albo użyj buildu z wkompilowanym kluczem)")
	}
	return out, nil
}
