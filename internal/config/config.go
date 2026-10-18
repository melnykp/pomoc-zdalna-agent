// Package config obsługuje config.json agenta (docs/ARCHITECTURE.md).
//
// ACL katalogu danych (tylko SYSTEM i Administratorzy) ustawia instalator przez svc.SecureDir.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ProductName to nazwa produktu widoczna dla klienta (okna, usługi, właściwości pliku).
const ProductName = "Piotr Melnyk IT - POMOC Zdalna"

// ProductDirName to nazwa katalogów produktu w Program Files i ProgramData (Windows).
const ProductDirName = ProductName

// linuxDirName to katalog danych poza Windows: krótki i bez spacji.
const linuxDirName = "pomoc-zdalna"

// Silniki pulpitu (to samo co wire.RemoteEngine*; config nie importuje wire).
const (
	RemoteEngineRustDesk = "rustdesk"
	RemoteEngineWebRTC   = "webrtc"
)

// Poziomy uprawnień pomocnika pulpitu (to samo co wire.HelperLevel*). Żaden nie jest kontem SYSTEM.
const (
	// DesktopHelperIntegrity: ZWYKŁY (filtrowany) token użytkownika z podniesioną do wysokiej integralnością, bez grupy Administratorzy
	// i z odjętymi uprawnieniami. UIPI porównuje tylko integralność, więc pomocnik może sterować oknami administratora, a po jego
	// przejęciu napastnik nie dostaje praw administratora. Włączany świadomie dla komputera bez nadzoru (serwer); na komputerze z
	// użytkownikiem przy klawiaturze ten poziom pomocnik dostaje tylko na czas sesji, za zgodą użytkownika (prośba w widzu).
	DesktopHelperIntegrity = "integrity"
	// DesktopHelperAdmin: pomocnik z podniesionym tokenem TEGO SAMEGO użytkownika (połączony token UAC, grupa Administratorzy włączona).
	// Tylko jako świadomy wybór, gdy "integrity" nie wystarcza do okien administratora.
	DesktopHelperAdmin = "admin"
	// DesktopHelperUser: token średniej integralności (jak w 0.4.2). Domyślny (także pusty): żadna aktualizacja nie podnosi uprawnień
	// po cichu. Wejście do okien administratora jest blokowane przez UIPI, dopóki użytkownik nie zezwoli na prośbę inżyniera.
	// Gdy token użytkownika jest podniesiony (UAC wyłączone), pomocnik dostaje jego odchudzoną wersję, nigdy pełny token.
	DesktopHelperUser = "user"
)

// Pierścienie wdrożeń.
const (
	RingCanary  = "canary"
	RingPilot   = "pilot"
	RingGeneral = "general"
)

// Config to zawartość config.json.
type Config struct {
	ServerURL        string   `json:"server_url"`
	DeviceID         string   `json:"device_id,omitempty"`
	Ring             string   `json:"ring"`
	HeartbeatSeconds int      `json:"heartbeat_s"`
	InventoryHours   int      `json:"inventory_h"`
	Whitelist        []string `json:"whitelist"`
	LogLevel         string   `json:"log_level"`
	// RemoteEngine wybiera silnik pulpitu: "rustdesk" (domyślnie, pusty tekst) albo "webrtc" (własny silnik,
	// docs/adr/0009). Zmiana działa od następnego startu agenta.
	RemoteEngine string `json:"remote_engine,omitempty"`
	// DesktopHelperLevel: "user" (domyślnie, także pusty), "integrity" albo "admin"; zmiana działa od następnego startu agenta.
	DesktopHelperLevel string `json:"desktop_helper_level,omitempty"`
	// ServerKeys to klucze publiczne serwera zapisane przy rejestracji. Gdy do agenta wkompilowano klucze
	// (internal/trust), mają pierwszeństwo, a te służą tylko w buildach rozwojowych.
	ServerKeys []ServerKey `json:"server_keys,omitempty"`
}

// Default zwraca ustawienia startowe (bez adresu serwera).
func Default() Config {
	return Config{
		Ring:             RingGeneral,
		HeartbeatSeconds: 30,
		InventoryHours:   6,
		Whitelist:        []string{},
		LogLevel:         "info",
	}
}

// DataDir zwraca katalog danych: %ProgramData%\<Nazwa> na Windows, /var/lib/<nazwa> gdzie indziej.
// Zmienna RMM_DATA_DIR nadpisuje go na potrzeby rozwoju i testów.
func DataDir() string {
	if dir := os.Getenv("RMM_DATA_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(programDataDir(), ProductDirName)
	}
	return filepath.Join("/var/lib", linuxDirName)
}

// Path zwraca ścieżkę config.json.
func Path() string { return filepath.Join(DataDir(), "config.json") }

// Load wczytuje i waliduje konfigurację.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: zły JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save zapisuje konfigurację atomowo (plik tymczasowy + rename).
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate sprawdza spójność konfiguracji. Adres serwera musi używać https,
// z wyjątkiem localhost na potrzeby rozwoju.
func (c Config) Validate() error {
	var errs []error
	if c.ServerURL == "" {
		errs = append(errs, errors.New("config: server_url jest wymagany"))
	} else if u, err := url.Parse(c.ServerURL); err != nil || u.Host == "" {
		errs = append(errs, fmt.Errorf("config: server_url nie jest adresem URL: %q", c.ServerURL))
	} else if u.Scheme != "https" && !isLocalhost(u.Hostname()) {
		errs = append(errs, fmt.Errorf("config: server_url musi używać https: %q", c.ServerURL))
	}
	if c.HeartbeatSeconds < 5 || c.HeartbeatSeconds > 600 {
		errs = append(errs, fmt.Errorf("config: heartbeat_s poza zakresem 5..600: %d", c.HeartbeatSeconds))
	}
	if c.InventoryHours < 1 || c.InventoryHours > 168 {
		errs = append(errs, fmt.Errorf("config: inventory_h poza zakresem 1..168: %d", c.InventoryHours))
	}
	switch c.Ring {
	case RingCanary, RingPilot, RingGeneral:
	default:
		errs = append(errs, fmt.Errorf("config: nieznany pierścień %q", c.Ring))
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("config: nieznany poziom logów %q", c.LogLevel))
	}
	switch c.RemoteEngine {
	case "", RemoteEngineRustDesk, RemoteEngineWebRTC:
	default:
		errs = append(errs, fmt.Errorf("config: nieznany silnik pulpitu %q", c.RemoteEngine))
	}
	switch c.DesktopHelperLevel {
	case "", DesktopHelperIntegrity, DesktopHelperAdmin, DesktopHelperUser:
	default:
		errs = append(errs, fmt.Errorf("config: nieznany poziom uprawnień pomocnika %q", c.DesktopHelperLevel))
	}
	return errors.Join(errs...)
}

// HelperLevel zwraca skuteczny poziom uprawnień pomocnika: pusty tekst oznacza domyślny "user" (stare konfiguracje nie
// dostają podniesionych uprawnień po cichu).
func (c Config) HelperLevel() string {
	switch c.DesktopHelperLevel {
	case DesktopHelperIntegrity:
		return DesktopHelperIntegrity
	case DesktopHelperAdmin:
		return DesktopHelperAdmin
	}
	return DesktopHelperUser
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// ServerKey to klucz publiczny serwera (Ed25519, 32 bajty w base64).
type ServerKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// ChannelURL zwraca adres kanału agenta wyprowadzony z server_url: https→wss, http→ws.
func (c Config) ChannelURL() (string, error) {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("config: server_url nie jest adresem URL: %q", c.ServerURL)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("config: nieobsługiwany schemat %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/agent"
	u.RawQuery = ""
	return u.String(), nil
}
