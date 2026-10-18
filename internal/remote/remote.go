// Package remote nadzoruje moduł pulpitu (klient RustDesk instalowany i konfigurowany przez agenta) i realizuje przebieg
// „Połącz” (docs/adr/0008-sterowanie-zdalne-rustdesk.md): hasło jednorazowe per sesja, zamknięcie dostępu po sesji,
// zgłaszanie stanu sesji.
//
// Komputer jest „zamknięty”: RustDesk ma ustawione losowe hasło, którego nikt nie zna. Sesja zaczyna się od polecenia
// remote.open: agent ustawia nowe hasło jednorazowe (OTP) i odsyła je razem z identyfikatorem RustDesk. Po rozłączeniu
// albo po upływie czasu życia hasła agent zamyka dostęp z powrotem.
package remote

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Module to sterowanie klientem pulpitu na tym komputerze.
type Module interface {
	// Installed mówi, czy klient pulpitu jest zainstalowany.
	Installed() bool
	// ID zwraca identyfikator RustDesk tego komputera.
	ID(ctx context.Context) (string, error)
	// SetPassword ustawia hasło stałe klienta (OTP sesji albo losowe hasło zamykające).
	SetPassword(ctx context.Context, password string) error
	// EnsureConfig wymusza adres naszego serwera i bezpieczne opcje klienta (patrz DefaultOptions).
	EnsureConfig(ctx context.Context) error
	// Running mówi, czy usługa klienta działa.
	Running(ctx context.Context) bool
	// Connected mówi, czy w tej chwili trwa połączenie przychodzące.
	Connected(ctx context.Context) (bool, error)
}

// Installer to moduł, który potrafi zainstalować klienta z pliku (RustDesk).
type Installer interface {
	Install(ctx context.Context, installerPath string) error
}

// VersionedInstaller to moduł, który przy instalacji chce znać wersję komponentu (zapisuje ją obok pliku, żeby nie
// uruchamiać pliku dla odczytu wersji).
type VersionedInstaller interface {
	InstallVersion(ctx context.Context, installerPath, version string) error
}

// Versioner to moduł, który zna wersję zainstalowanego klienta.
type Versioner interface {
	Version(ctx context.Context) string
}

// EngineNamer to moduł, który nazywa swój silnik dla panelu (wire.RemoteEngine*). Bez tego przyjmujemy RustDesk.
type EngineNamer interface {
	Engine() string
}

// Signaler to moduł z sygnalizacją WebRTC (własny silnik): oferta widza daje odpowiedź z odciskiem DTLS, kandydat
// ICE nie daje odpowiedzi (nil).
type Signaler interface {
	Signal(ctx context.Context, sessionID string, sig wire.RemoteSignal) (*wire.RemoteSignal, error)
}

// SessionEnder to moduł, który przy końcu sesji zamyka własne połączenie i oddaje statystyki do audytu.
type SessionEnder interface {
	EndSession(ctx context.Context) *wire.RemoteStats
}

// Błędy menedżera sesji.
var (
	// ErrNotInstalled: klient pulpitu nie jest zainstalowany na tym komputerze.
	ErrNotInstalled = errors.New("remote: moduł pulpitu nie jest zainstalowany")
	// ErrBusy: trwa inna sesja pulpitu.
	ErrBusy = errors.New("remote: trwa inna sesja pulpitu")
	// ErrNoSession: brak sesji o podanym identyfikatorze.
	ErrNoSession = errors.New("remote: brak takiej sesji")
	// ErrNoInstaller: ten moduł nie umie instalować klienta.
	ErrNoInstaller = errors.New("remote: moduł nie obsługuje instalacji")
)

// Stany sesji zgłaszane serwerowi (wire.RemoteState.State).
const (
	StateConnected    = "connected"    // inżynier się połączył
	StateDisconnected = "disconnected" // inżynier się rozłączył, dostęp zamknięty
	StateExpired      = "expired"      // nikt się nie połączył w czasie życia hasła, dostęp zamknięty
	StateClosed       = "closed"       // sesja zamknięta poleceniem remote.close, dostęp zamknięty
)

// Session to jedna sesja zdalna od remote.open do zamknięcia dostępu.
type Session struct {
	ID          string
	RemoteID    string
	OTP         string
	ExpiresAt   time.Time
	ConnectedAt time.Time
	// Engine to silnik sesji (wire.RemoteEngine*), przekazywany panelowi w remote.otp.
	Engine string
	// ctx gaśnie z końcem sesji (sygnalizacja w toku ma się wtedy przerwać); tylko do użytku Managera.
	ctx    context.Context
	cancel context.CancelFunc
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
