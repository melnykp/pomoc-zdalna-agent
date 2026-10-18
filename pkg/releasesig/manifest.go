package releasesig

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Komponenty podlegające aktualizacji (docs/ARCHITECTURE.md).
const (
	ComponentAgent        = "agent"
	ComponentWatchdog     = "watchdog"
	ComponentRemoteModule = "remote_module"
	// ComponentDesktopHelper to pomocnik pulpitu własnego silnika (desktop-helper.exe, ADR-0009). Osobny komponent, bo ma
	// własną numerację wersji (tę samą co agent) i instaluje się niezależnie od tego, który silnik jest włączony.
	ComponentDesktopHelper = "desktop_helper"
)

// SchemaVersion to wersja formatu manifestu.
const SchemaVersion = 1

// Artifact opisuje plik wydania.
type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Requires to minimalne wersje komponentów towarzyszących.
type Requires struct {
	WatchdogMin string `json:"watchdog_min,omitempty"`
}

// Manifest to podpisywany opis wydania.
type Manifest struct {
	Schema    int      `json:"schema"`
	Component string   `json:"component"`
	Version   string   `json:"version"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Artifact  Artifact `json:"artifact"`
	Requires  Requires `json:"requires"`
	// MinVersion to próg bezpieczeństwa: po zobaczeniu tego manifestu agent nigdy nie zainstaluje wersji niższej.
	// Chroni przed przejętym serwerem, który ofiarowałby starszą, ale poprawnie podpisaną wersję z luką.
	MinVersion          string `json:"min_version,omitempty"`
	AuthenticodeSubject string `json:"authenticode_subject"`
	ReleasedAt          string `json:"released_at"`
	Notes               string `json:"notes,omitempty"`
}

// ParseManifest dekoduje i waliduje manifest. Bajty raw należy zachować bez zmian,
// bo to one (nie ponownie zakodowana struktura) są objęte podpisem.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: zły JSON: %w", err)
	}
	return m, m.Validate()
}

// Validate sprawdza kompletność manifestu.
func (m Manifest) Validate() error {
	var errs []error
	if m.Schema != SchemaVersion {
		errs = append(errs, fmt.Errorf("manifest: nieobsługiwany schema %d", m.Schema))
	}
	switch m.Component {
	case ComponentAgent, ComponentWatchdog, ComponentRemoteModule, ComponentDesktopHelper:
	default:
		errs = append(errs, fmt.Errorf("manifest: nieznany komponent %q", m.Component))
	}
	if m.Version == "" {
		errs = append(errs, errors.New("manifest: brak wersji"))
	}
	if m.OS == "" || m.Arch == "" {
		errs = append(errs, errors.New("manifest: brak os/arch"))
	}
	if m.Artifact.URL == "" || len(m.Artifact.SHA256) != 64 || m.Artifact.Size <= 0 {
		errs = append(errs, errors.New("manifest: niekompletny artefakt (url, sha256 hex 64, size > 0)"))
	}
	if _, err := CompareVersions(m.Version, m.Version); m.Version != "" && err != nil {
		errs = append(errs, fmt.Errorf("manifest: wersja %q nie jest w formacie semver", m.Version))
	}
	if m.MinVersion != "" {
		if c, err := CompareVersions(m.MinVersion, m.Version); err != nil {
			errs = append(errs, fmt.Errorf("manifest: min_version: %w", err))
		} else if c > 0 {
			errs = append(errs, fmt.Errorf("manifest: min_version %s jest wyższe niż version %s", m.MinVersion, m.Version))
		}
	}
	if m.AuthenticodeSubject == "" {
		errs = append(errs, errors.New("manifest: brak authenticode_subject"))
	}
	return errors.Join(errs...)
}

// Matches sprawdza, czy manifest dotyczy tego komponentu i tej platformy.
func (m Manifest) Matches(component, goos, goarch string) error {
	if m.Component != component {
		return fmt.Errorf("manifest: komponent %q, oczekiwano %q", m.Component, component)
	}
	if m.OS != goos || m.Arch != goarch {
		return fmt.Errorf("manifest: platforma %s/%s, oczekiwano %s/%s", m.OS, m.Arch, goos, goarch)
	}
	return nil
}
