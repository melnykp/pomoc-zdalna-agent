package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

// Download pobiera artefakt z manifestu do dest. Plik powstaje pod nazwą tymczasową i trafia pod docelową dopiero
// po sprawdzeniu rozmiaru i sumy SHA-256, więc w staging nie leży nic niezweryfikowanego. Rozmiar z manifestu jest
// twardym limitem: serwer nie może przysłać więcej bajtów, niż podpisano.
func Download(ctx context.Context, client *http.Client, m releasesig.Manifest, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	part := dest + ".part"
	_ = os.Remove(part)
	defer os.Remove(part)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Artifact.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rmm-agent")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("update: pobieranie: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("update: serwer odpowiedział %s", res.Status)
	}
	if res.ContentLength >= 0 && res.ContentLength != m.Artifact.Size {
		return fmt.Errorf("update: serwer podaje %d B, manifest %d B", res.ContentLength, m.Artifact.Size)
	}

	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, m.Artifact.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("update: zapis pobranego pliku: %w", err)
	}
	if n != m.Artifact.Size {
		return fmt.Errorf("update: pobrano %d B, manifest %d B", n, m.Artifact.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, m.Artifact.SHA256) {
		return fmt.Errorf("update: suma SHA-256 %s, manifest %s", got, strings.ToLower(m.Artifact.SHA256))
	}
	_ = os.Remove(dest)
	return os.Rename(part, dest)
}
