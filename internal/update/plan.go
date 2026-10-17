package update

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// ErrUpToDate oznacza, że oferowana wersja jest już uruchomiona.
var ErrUpToDate = errors.New("update: ta wersja jest już uruchomiona")

// ErrBelowFloor oznacza ofertę niższą niż próg bezpieczeństwa zapamiętany z wcześniej widzianego manifestu.
var ErrBelowFloor = errors.New("update: wersja poniżej progu bezpieczeństwa")

// ErrUnsupportedComponent: ta wersja agenta aktualizuje tylko własny plik (komponent agent).
var ErrUnsupportedComponent = errors.New("update: nieobsługiwany komponent")

// Planner sprawdza ofertę wydania zanim cokolwiek zostanie pobrane.
type Planner struct {
	// Signers to zaufane klucze podpisu wydań (wkompilowane; releasesig.TrustedSigners).
	Signers        []ssh.PublicKey
	CurrentVersion string
	// ServerURL to adres bramki z konfiguracji; artefakt musi leżeć na tym samym serwerze.
	ServerURL string
	// Floor to zapamiętany próg bezpieczeństwa (Paths.Floor); oferta niższa od niego jest odrzucana.
	Floor    string
	OS, Arch string
}

// Plan weryfikuje ofertę: podpis sshsig manifestu, zgodność komponentu, platformy i wersji, adres artefaktu.
// Zwraca manifest tylko wtedy, gdy wszystkie sprawdzenia przeszły. Manifest jest parsowany z tych samych
// bajtów, które podpisano, a nie z ponownie zakodowanej struktury.
func (p Planner) Plan(o wire.ReleaseAvailable) (releasesig.Manifest, error) {
	if o.Component != releasesig.ComponentAgent {
		return releasesig.Manifest{}, fmt.Errorf("%w: %q", ErrUnsupportedComponent, o.Component)
	}
	if _, err := releasesig.VerifySSHSig([]byte(o.Manifest), []byte(o.Signature), p.Signers); err != nil {
		return releasesig.Manifest{}, err
	}
	m, err := releasesig.ParseManifest([]byte(o.Manifest))
	if err != nil {
		return releasesig.Manifest{}, err
	}
	if err := m.Matches(releasesig.ComponentAgent, p.OS, p.Arch); err != nil {
		return releasesig.Manifest{}, err
	}
	if m.Version != o.Version {
		return releasesig.Manifest{}, fmt.Errorf("update: wersja w manifeście (%s) różni się od oferowanej (%s)", m.Version, o.Version)
	}
	if m.Version == p.CurrentVersion {
		return releasesig.Manifest{}, ErrUpToDate
	}
	if p.Floor != "" {
		c, err := releasesig.CompareVersions(m.Version, p.Floor)
		if err != nil {
			return releasesig.Manifest{}, err
		}
		if c < 0 {
			return releasesig.Manifest{}, fmt.Errorf("%w: oferta %s, próg %s", ErrBelowFloor, m.Version, p.Floor)
		}
	}
	if err := p.checkArtifactURL(m.Artifact.URL); err != nil {
		return releasesig.Manifest{}, err
	}
	return m, nil
}

// checkArtifactURL wymaga adresu na tym samym serwerze co bramka agenta, pod ścieżką artefaktów, po https
// (http tylko dla localhost w rozwoju). Manifest jest podpisany, ale obrona w głąb nic nie kosztuje.
func (p Planner) checkArtifactURL(raw string) error {
	art, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("update: zły adres artefaktu: %w", err)
	}
	srv, err := url.Parse(p.ServerURL)
	if err != nil || srv.Host == "" {
		return fmt.Errorf("update: zły adres serwera %q", p.ServerURL)
	}
	if !strings.EqualFold(art.Host, srv.Host) {
		return fmt.Errorf("update: artefakt na obcym serwerze %s (oczekiwano %s)", art.Host, srv.Host)
	}
	if art.Scheme != "https" && !(art.Scheme == "http" && isLocal(art.Hostname())) {
		return fmt.Errorf("update: artefakt musi być pobierany po https (jest %s)", art.Scheme)
	}
	if !strings.HasPrefix(art.Path, "/v1/releases/artifacts/") || art.RawQuery != "" || art.Fragment != "" {
		return errors.New("update: adres artefaktu poza /v1/releases/artifacts/")
	}
	return nil
}

func isLocal(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
