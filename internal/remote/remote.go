// Package remote nadzoruje moduł pulpitu (własna kompilacja RustDesk) i realizuje
// przebieg „Połącz” z docs/ARCHITECTURE.md: hasło jednorazowe per sesja, whitelist
// identyfikatorów inżynierów, zgłaszanie stanu sesji.
//
// Szkielet: interfejs modułu, model sesji i generator OTP. Implementacja na rustdesk.exe
// wymaga potwierdzenia flag CLI i nazw opcji na bieżącej wersji.
package remote

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"
)

// Module to sterowanie procesem pulpitu.
type Module interface {
	// ID zwraca identyfikator RustDesk urządzenia.
	ID(ctx context.Context) (string, error)
	// SetPassword ustawia hasło stałe (OTP sesji albo losowe „zamknięcie”).
	SetPassword(ctx context.Context, password string) error
	// EnsureConfig wymusza opcje z defaults.toml i listę dozwolonych inżynierów.
	EnsureConfig(ctx context.Context, whitelist []string) error
	// Running mówi, czy usługa modułu działa.
	Running(ctx context.Context) (bool, error)
}

// Session to jedna sesja zdalna od remote.open do rozłączenia.
type Session struct {
	ID                 string
	TechnicianRemoteID string
	OTP                string
	ExpiresAt          time.Time
	ConnectedAt        time.Time
	EndedAt            time.Time
}

// otpAlphabet pomija znaki łatwe do pomylenia (0/O, 1/l/I).
const otpAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// OTPLength to długość hasła sesji.
const OTPLength = 24

// GenerateOTP zwraca losowe hasło o długości n bez obciążenia rozkładu.
func GenerateOTP(n int) (string, error) {
	max := big.NewInt(int64(len(otpAlphabet)))
	out := make([]byte, n)
	for i := range out {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = otpAlphabet[k.Int64()]
	}
	return string(out), nil
}

// LockPassword zwraca losowe hasło, którego nikt nie zna: ustawiane po sesji
// i po wygaśnięciu OTP, żeby komputer nie był dostępny bez panelu.
func LockPassword() (string, error) {
	return GenerateOTP(48)
}
