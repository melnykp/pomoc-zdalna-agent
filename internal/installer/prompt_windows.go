//go:build windows

package installer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// PromptToken pokazuje okno z prośbą o wklejenie kodu zaproszenia. Używane, gdy plik nie niesie zaproszenia ani w nazwie,
// ani w adresie pobrania (np. po skopiowaniu z innego miejsca). Okno to InputBox z PowerShella, który jest w każdym Windows.
func PromptToken(ctx context.Context) (string, bool) {
	const script = "Add-Type -AssemblyName Microsoft.VisualBasic; " +
		"[Microsoft.VisualBasic.Interaction]::InputBox('Wklej kod zaproszenia ze strony pobierania (albo cały link zaproszenia).', 'Piotr Melnyk IT - POMOC Zdalna', '')"
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = "C:/Windows"
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return TokenFromText(string(out))
}

// RunningInstalledCopy mówi, czy bieżący plik to zainstalowany agent albo nadzorca. Wtedy nie pytamy o zaproszenie.
func RunningInstalledCopy() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	exe = filepath.Clean(exe)
	return equalPath(exe, InstalledExe()) || equalPath(exe, InstalledWatchdogExe())
}

func equalPath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
