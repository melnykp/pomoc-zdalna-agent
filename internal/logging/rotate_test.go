package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatorKeepsBoundedFilesAndNewestData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	r, err := newRotator(path, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := r.Write([]byte(fmt.Sprintf("linia-%02d-%s\n", i, strings.Repeat("x", 20)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 4 {
		t.Fatalf("oczekiwano agent.log + 3 archiwa, jest %d plików", len(entries))
	}
	cur, _ := os.ReadFile(path)
	if !strings.Contains(string(cur), "linia-39") {
		t.Fatalf("najnowszy wpis powinien być w bieżącym pliku: %q", cur)
	}
	for _, e := range entries {
		info, _ := e.Info()
		if info.Size() > 100+40 {
			t.Errorf("%s ma %d B, limit rotacji 100 B + jeden wpis", e.Name(), info.Size())
		}
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Fatal("nie powinno być więcej archiwów niż keep")
	}
}

func TestRotatorResumesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 90)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := newRotator(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Write([]byte(strings.Repeat("b", 30))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("po przekroczeniu limitu stary plik powinien trafić do archiwum")
	}
}
