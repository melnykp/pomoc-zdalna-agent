//go:build !windows

package svc

import (
	"errors"
	"fmt"
	"os"
)

// ErrUnsupported oznacza czynność dostępną tylko w Windows.
var ErrUnsupported = errors.New("svc: dostępne tylko w systemie Windows")

// IsWindowsService: poza Windows nigdy.
func IsWindowsService() bool { return false }

// RunService poza Windows działa jak tryb pierwszoplanowy.
func RunService(_ string, r Runner) error { return RunForeground(r) }

// IsAdmin mówi, czy proces działa jako root.
func IsAdmin() bool { return os.Geteuid() == 0 }

// Elevate nie jest dostępne poza Windows.
func Elevate(string, []string) error { return ErrUnsupported }

// Install nie jest dostępne poza Windows.
func Install(string, string, string, string, ...string) error { return ErrUnsupported }

// Uninstall nie jest dostępne poza Windows.
func Uninstall(string) error { return ErrUnsupported }

// Start nie jest dostępne poza Windows.
func Start(string) error { return ErrUnsupported }

// Stop nie jest dostępne poza Windows.
func Stop(string) error { return ErrUnsupported }

// Exists: poza Windows nie ma usług do sprawdzenia.
func Exists(string) bool { return false }

// SecureDir poza Windows ustawia tryb 0700.
func SecureDir(path string) error { return os.Chmod(path, 0o700) }

// Message wypisuje komunikat na standardowe wyjście.
func Message(title, text string, _ bool) { fmt.Printf("%s\n%s\n", title, text) }

// Delete nie jest dostępne poza Windows.
func Delete(string) error { return ErrUnsupported }

// IsRunning: poza Windows nie ma usług.
func IsRunning(string) bool { return false }

// IsWindowsServiceCapable: poza Windows nie ma menedżera usług.
func IsWindowsServiceCapable() bool { return false }

// AttachParentConsole: poza Windows nic do zrobienia.
func AttachParentConsole() {}
