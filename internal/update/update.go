// Package update realizuje przebieg aktualizacji z docs/ARCHITECTURE.md: weryfikacja oferty (podpis sshsig,
// platforma, wersja, adres), pobranie ze sprawdzeniem rozmiaru i sumy, Authenticode oraz wymiana plików stanu
// z watchdogiem, który sam wykonuje podmianę i rollback.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

// VerifyFile sprawdza, że plik ma dokładnie oczekiwany rozmiar i sumę SHA-256.
func VerifyFile(path string, want releasesig.Artifact) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != want.Size {
		return fmt.Errorf("update: rozmiar %d, oczekiwano %d", st.Size(), want.Size)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want.SHA256) {
		return fmt.Errorf("update: sha256 %s, oczekiwano %s", got, strings.ToLower(want.SHA256))
	}
	return nil
}

// SHA256File liczy sumę pliku (używane przez narzędzia i testy).
func SHA256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
