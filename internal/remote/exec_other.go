//go:build !windows

package remote

import "os/exec"

// hideWindow poza Windows nic nie robi.
func hideWindow(*exec.Cmd) {}

// DefaultExe poza Windows (tryb rozwojowy).
func DefaultExe() string { return "/usr/bin/rustdesk" }

// processCommandLines poza Windows nie wykrywa procesów (moduł pulpitu jest tylko dla Windows).
func processCommandLines(string) ([]string, error) { return nil, nil }
