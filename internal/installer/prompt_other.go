//go:build !windows

package installer

import "context"

// PromptToken poza Windows nie pyta o nic.
func PromptToken(context.Context) (string, bool) { return "", false }

// RunningInstalledCopy poza Windows zawsze zwraca true, żeby nie pytać o zaproszenie.
func RunningInstalledCopy() bool { return true }
