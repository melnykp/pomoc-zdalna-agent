// Package inventory zbiera inwentaryzację do wiadomości inventory.full
// (docs/ARCHITECTURE.md).
//
// Dane wspólne zbiera kod przenośny. Część specyficzną dla Windows (rejestr, dyski, oprogramowanie, status
// Defendera) dokłada inventory_windows.go bez WMI i COM, same wywołania systemowe i rejestr.
// Do ewentualnego dodania przez WMI: numer seryjny BIOS, status BitLockera.
package inventory

import (
	"context"
	"net"
	"os"
	"runtime"
	"time"
)

// OS opisuje system operacyjny.
type OS struct {
	Family       string    `json:"family"`
	Version      string    `json:"version"`
	Build        string    `json:"build"`
	Arch         string    `json:"arch"`
	Hostname     string    `json:"hostname"`
	InstallDate  time.Time `json:"install_date,omitempty"`
	LastBootTime time.Time `json:"last_boot_time,omitempty"`
}

// Hardware opisuje sprzęt.
type Hardware struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	BIOSVersion  string `json:"bios_version"`
	CPU          string `json:"cpu"`
	CPUCores     int    `json:"cpu_cores"`
	MemTotalMB   int64  `json:"mem_total_mb"`
	UUID         string `json:"uuid"`
}

// Disk to wolumin logiczny.
type Disk struct {
	Mount      string `json:"mount"`
	FS         string `json:"fs"`
	TotalBytes int64  `json:"total_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
}

// NetworkAdapter to karta sieciowa z adresami.
type NetworkAdapter struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
	DHCP bool     `json:"dhcp"`
}

// Software to pozycja z listy zainstalowanego oprogramowania.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstalledOn string `json:"installed_on,omitempty"` // YYYY-MM-DD
}

// Security to status zabezpieczeń (tylko status, bez treści).
type Security struct {
	DefenderOn      bool   `json:"defender_on"`
	BitLockerStatus string `json:"bitlocker_status"`
}

// Inventory to pełny snapshot.
type Inventory struct {
	CollectedAt time.Time        `json:"collected_at"`
	OS          OS               `json:"os"`
	Hardware    Hardware         `json:"hardware"`
	Disks       []Disk           `json:"disks"`
	Network     []NetworkAdapter `json:"network"`
	Software    []Software       `json:"software"`
	Security    Security         `json:"security"`
	LoggedUser  string           `json:"logged_user"`
}

// Collect zbiera inwentaryzację. Część wspólna (hostname, system, adresy) działa wszędzie,
// reszta (rejestr, dyski, oprogramowanie) jest uzupełniana przez kod platformy.
func Collect(ctx context.Context) (Inventory, error) {
	if err := ctx.Err(); err != nil {
		return Inventory{}, err
	}
	host, _ := os.Hostname()
	inv := Inventory{
		CollectedAt: time.Now().UTC(),
		OS: OS{
			Family:   runtime.GOOS,
			Arch:     runtime.GOARCH,
			Hostname: host,
		},
		Hardware: Hardware{CPUCores: runtime.NumCPU()},
		Disks:    []Disk{},
		Network:  collectNetwork(),
		Software: []Software{},
	}
	collectPlatform(ctx, &inv)
	return inv, ctx.Err()
}

// collectNetwork opisuje karty z adresami; interfejsy loopback i wyłączone są pomijane.
func collectNetwork() []NetworkAdapter {
	out := []NetworkAdapter{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		a := NetworkAdapter{Name: i.Name, MAC: i.HardwareAddr.String(), IPs: []string{}}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				a.IPs = append(a.IPs, ipn.IP.String())
			}
		}
		out = append(out, a)
	}
	return out
}
