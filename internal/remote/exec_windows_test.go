//go:build windows

package remote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Na prawdziwym systemie: własny proces testowy musi być widoczny z linią poleceń zawierającą flagi testowe.
func TestProcessCommandLinesSeesOwnProcess(t *testing.T) {
	lines, err := processCommandLines(filepath.Base(os.Args[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Fatal("własny proces testowy powinien być na liście")
	}
	found := false
	for _, l := range lines {
		if strings.Contains(l, "-test.") {
			found = true
		}
	}
	if !found {
		t.Fatalf("linia poleceń powinna zawierać flagi testowe, jest: %q", lines)
	}
}

func TestProcessCommandLinesForMissingImageIsEmpty(t *testing.T) {
	lines, err := processCommandLines("nie-ma-takiego-programu-12345.exe")
	if err != nil || len(lines) != 0 {
		t.Fatalf("lines=%v err=%v", lines, err)
	}
}

func TestDefaultExeUsesProgramFiles(t *testing.T) {
	if got := DefaultExe(); !strings.HasSuffix(got, filepath.Join("RustDesk", "rustdesk.exe")) {
		t.Fatalf("DefaultExe: %q", got)
	}
}
