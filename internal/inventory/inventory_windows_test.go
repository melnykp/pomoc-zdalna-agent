//go:build windows

package inventory

import (
	"context"
	"testing"
)

// Test na prawdziwym Windows: odczyt jest tylko do odczytu, niczego nie zmienia w systemie.
func TestCollectOnWindows(t *testing.T) {
	inv, err := Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.Version == "" || inv.OS.Build == "" {
		t.Errorf("brak wersji systemu: %+v", inv.OS)
	}
	if len(inv.Disks) == 0 {
		t.Error("brak dysków stałych")
	}
	for _, d := range inv.Disks {
		if d.TotalBytes <= 0 || d.FreeBytes < 0 || d.FreeBytes > d.TotalBytes || d.Mount == "" {
			t.Errorf("dysk niespójny: %+v", d)
		}
	}
	if len(inv.Software) == 0 {
		t.Error("brak oprogramowania z rejestru")
	}
	if inv.Hardware.MemTotalMB <= 0 || inv.Hardware.UUID == "" {
		t.Errorf("sprzęt: %+v", inv.Hardware)
	}
	if HardwareID() == "" {
		t.Error("brak MachineGuid")
	}
	t.Logf("system: %s (%s), %d dysków, %d programów, CPU: %s, RAM: %d MB, model: %s %s",
		inv.OS.Version, inv.OS.Build, len(inv.Disks), len(inv.Software), inv.Hardware.CPU, inv.Hardware.MemTotalMB, inv.Hardware.Manufacturer, inv.Hardware.Model)
}
