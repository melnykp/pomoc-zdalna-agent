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
	return errors.Join(errs...)
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
