package update

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

func TestVerifyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.exe")
	if err := os.WriteFile(path, []byte("udawany artefakt"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}

	good := releasesig.Artifact{SHA256: sum, Size: size}
	if err := VerifyFile(path, good); err != nil {
		t.Fatalf("poprawny plik odrzucony: %v", err)
	}
	upper := good
	upper.SHA256 = toUpper(sum)
	if err := VerifyFile(path, upper); err != nil {
		t.Fatalf("suma wielkimi literami powinna być akceptowana: %v", err)
	}
	badSize := good
	badSize.Size++
	if err := VerifyFile(path, badSize); err == nil {
		t.Fatal("zły rozmiar przyjęty")
	}
	badSum := good
	badSum.SHA256 = "0" + sum[1:]
	if badSum.SHA256 == sum {
		badSum.SHA256 = "1" + sum[1:]
	}
	if err := VerifyFile(path, badSum); err == nil {
		t.Fatal("zła suma przyjęta")
	}
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
