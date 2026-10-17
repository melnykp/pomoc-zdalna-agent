package watchdog

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

// verifiedManifest sprawdza podpis sshsig manifestu dołączonego do prośby i zgodność prośby z nim. Zwraca manifest,
// z którego watchdog bierze sumę, rozmiar i podmiot Authenticode.
func (w *Watchdog) verifiedManifest(req update.Request) (releasesig.Manifest, error) {
	if len(w.o.Signers) == 0 {
		return releasesig.Manifest{}, errors.New("brak zaufanych kluczy podpisu wydań w tym pliku: odmowa podmiany")
	}
	if _, err := releasesig.VerifySSHSig([]byte(req.Manifest), []byte(req.Signature), w.o.Signers); err != nil {
		return releasesig.Manifest{}, fmt.Errorf("podpis manifestu w prośbie: %w", err)
	}
	m, err := releasesig.ParseManifest([]byte(req.Manifest))
	if err != nil {
		return releasesig.Manifest{}, err
	}
	if err := m.Matches(releasesig.ComponentAgent, runtime.GOOS, runtime.GOARCH); err != nil {
		return releasesig.Manifest{}, err
	}
	if m.Component != req.Component || m.Version != req.Version || m.Artifact.SHA256 != req.SHA256 ||
		m.Artifact.Size != req.Size || m.AuthenticodeSubject != req.AuthenticodeSubject {
		return releasesig.Manifest{}, errors.New("prośba o podmianę nie zgadza się z podpisanym manifestem")
	}
	return m, nil
}
