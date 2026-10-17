package installer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/enroll"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/inventory"
)

// Params to dane do rejestracji urządzenia.
type Params struct {
	ServerURL string
	Token     string
	// DataDir to katalog danych agenta; pusty = config.DataDir().
	DataDir string
	Version string
	// HTTPClient pozwala podmienić klienta w testach. Domyślnie TLS 1.3.
	HTTPClient *http.Client
	Log        *slog.Logger
}

// Result opisuje wynik rejestracji.
type Result struct {
	DeviceID   string
	Status     string // pending albo approved
	ShortCode  string
	ConfigPath string
	// Repeated mówi, że urządzenie było już zarejestrowane i użyto zapisanej konfiguracji.
	Repeated bool
}

func osFamily() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

// Enroll tworzy tożsamość urządzenia, rejestruje je na serwerze z zaproszenia i zapisuje konfigurację.
// Ponowne uruchomienie na zarejestrowanym komputerze niczego nie zmienia i nie zużywa zaproszenia.
func Enroll(ctx context.Context, p Params) (Result, error) {
	dir := p.DataDir
	if dir == "" {
		dir = config.DataDir()
	}
	cfgPath := filepath.Join(dir, "config.json")
	log := p.Log
	if log == nil {
		log = slog.Default()
	}

	if cfg, err := config.Load(cfgPath); err == nil && cfg.DeviceID != "" && cfg.ServerURL == p.ServerURL {
		log.Info("komputer jest już zarejestrowany", "device_id", cfg.DeviceID)
		return Result{DeviceID: cfg.DeviceID, ShortCode: shortCode(cfg.DeviceID), ConfigPath: cfgPath, Repeated: true}, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("katalog danych: %w", err)
	}
	id, _, err := identity.LoadOrCreate(filepath.Join(dir, "identity.bin"))
	if err != nil {
		return Result{}, fmt.Errorf("tożsamość urządzenia: %w", err)
	}

	host, _ := os.Hostname()
	osVersion := ""
	if inv, err := inventory.Collect(ctx); err == nil {
		osVersion = inv.OS.Version
	}
	res, err := enroll.Do(ctx, p.HTTPClient, p.ServerURL, enroll.Request{
		InvitationToken: p.Token,
		PublicKey:       id.PublicBase64(),
		Hostname:        host,
		OSFamily:        osFamily(),
		OSVersion:       osVersion,
		Arch:            runtime.GOARCH,
		HwID:            inventory.HardwareID(),
		AgentVersion:    p.Version,
	})
	if err != nil {
		var e *enroll.Error
		if errors.As(err, &e) && e.Code == enroll.CodeAlreadyEnrolled {
			// Ten sam klucz urządzenia jest już na serwerze, ale lokalnej konfiguracji brak (np. po
			// skasowaniu pliku). Bez device_id nie da się jej odtworzyć, więc trzeba nowej tożsamości.
			return Result{}, fmt.Errorf("serwer zna już ten klucz urządzenia, ale brakuje lokalnej konfiguracji: %w", err)
		}
		return Result{}, err
	}

	cfg := config.Default()
	cfg.ServerURL = p.ServerURL
	cfg.DeviceID = res.DeviceID
	cfg.ServerKeys = res.ServerKeys
	if err := config.Save(cfgPath, cfg); err != nil {
		return Result{}, fmt.Errorf("zapis konfiguracji: %w", err)
	}
	code := res.ShortCode
	if code == "" {
		code = shortCode(res.DeviceID)
	}
	return Result{DeviceID: res.DeviceID, Status: res.Status, ShortCode: code, ConfigPath: cfgPath}, nil
}

func shortCode(deviceID string) string {
	if len(deviceID) < 8 {
		return deviceID
	}
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		c := deviceID[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}
