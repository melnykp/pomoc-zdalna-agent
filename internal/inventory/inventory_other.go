//go:build !windows

package inventory

import "context"

// collectPlatform: poza Windows zbieramy tylko dane wspólne (dev i testy).
func collectPlatform(context.Context, *Inventory) {}

// HardwareID zwraca stabilny identyfikator maszyny; poza Windows pusty.
func HardwareID() string { return "" }
