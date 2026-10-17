//go:build windows

package inventory

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/melnykp/pomoc-zdalna-agent/internal/metrics"
)

// HardwareID zwraca MachineGuid z rejestru: stabilny identyfikator instalacji systemu.
func HardwareID() string {
	return regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid", registry.QUERY_VALUE|registry.WOW64_64KEY)
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	collectOS(inv)
	collectHardware(inv)
	inv.Disks = collectDisks()
	if ctx.Err() != nil {
		return
	}
	inv.Software = collectSoftware(ctx)
	inv.Security = collectSecurity()
	inv.LoggedUser = metrics.NewSampler().Sample().LoggedUser
}

const (
	currentVersion = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	read64         = registry.QUERY_VALUE | registry.WOW64_64KEY
)

func regString(root registry.Key, path, name string, access uint32) string {
	k, err := registry.OpenKey(root, path, access)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func regInt(root registry.Key, path, name string, access uint32) (uint64, bool) {
	k, err := registry.OpenKey(root, path, access)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

func collectOS(inv *Inventory) {
	product := regString(registry.LOCAL_MACHINE, currentVersion, "ProductName", read64)
	build := regString(registry.LOCAL_MACHINE, currentVersion, "CurrentBuildNumber", read64)
	display := regString(registry.LOCAL_MACHINE, currentVersion, "DisplayVersion", read64)
	// ProductName w Windows 11 bywa nadal „Windows 10”; numer kompilacji >= 22000 oznacza Windows 11.
	if n := atoi(build); n >= 22000 && strings.Contains(product, "Windows 10") {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if ubr, ok := regInt(registry.LOCAL_MACHINE, currentVersion, "UBR", read64); ok && build != "" {
		build = fmt.Sprintf("%s.%d", build, ubr)
	}
	inv.OS.Version = strings.TrimSpace(product + " " + display)
	inv.OS.Build = build
	if sec, ok := regInt(registry.LOCAL_MACHINE, currentVersion, "InstallDate", read64); ok && sec > 0 {
		inv.OS.InstallDate = time.Unix(int64(sec), 0).UTC()
	}
	inv.OS.LastBootTime = time.Now().Add(-time.Duration(metrics.NewSampler().Sample().UptimeS) * time.Second).UTC()
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func collectHardware(inv *Inventory) {
	const bios = `HARDWARE\DESCRIPTION\System\BIOS`
	inv.Hardware.Manufacturer = regString(registry.LOCAL_MACHINE, bios, "SystemManufacturer", read64)
	inv.Hardware.Model = regString(registry.LOCAL_MACHINE, bios, "SystemProductName", read64)
	inv.Hardware.BIOSVersion = regString(registry.LOCAL_MACHINE, bios, "BIOSVersion", read64)
	inv.Hardware.CPU = regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString", read64)
	inv.Hardware.UUID = HardwareID()
	inv.Hardware.MemTotalMB = metrics.NewSampler().Sample().MemTotalMB
}

// collectDisks zwraca stałe wolumeny z ilością wolnego miejsca.
func collectDisks() []Disk {
	out := []Disk{}
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return out
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := fmt.Sprintf("%c:\\", 'A'+i)
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
			continue
		}
		fsName := make([]uint16, 32)
		_ = windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName)))
		out = append(out, Disk{Mount: fmt.Sprintf("%c:", 'A'+i), FS: windows.UTF16ToString(fsName), TotalBytes: int64(total), FreeBytes: int64(totalFree)})
	}
	return out
}

var dateRe = regexp.MustCompile(`^\d{8}$`)

// collectSoftware czyta klucze Uninstall w widoku 64- i 32-bitowym oraz bieżącego użytkownika usługi.
func collectSoftware(ctx context.Context) []Software {
	type src struct {
		root   registry.Key
		path   string
		access uint32
	}
	const uninstall = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	sources := []src{
		{registry.LOCAL_MACHINE, uninstall, registry.ENUMERATE_SUB_KEYS | registry.QUERY_VALUE | registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, uninstall, registry.ENUMERATE_SUB_KEYS | registry.QUERY_VALUE | registry.WOW64_32KEY},
	}
	seen := map[string]struct{}{}
	out := []Software{}
	for _, s := range sources {
		if ctx.Err() != nil {
			break
		}
		root, err := registry.OpenKey(s.root, s.path, s.access)
		if err != nil {
			continue
		}
		names, _ := root.ReadSubKeyNames(-1)
		root.Close()
		for _, n := range names {
			k, err := registry.OpenKey(s.root, s.path+`\`+n, registry.QUERY_VALUE|(s.access&(registry.WOW64_64KEY|registry.WOW64_32KEY)))
			if err != nil {
				continue
			}
			name, _, _ := k.GetStringValue("DisplayName")
			sysComp, _, _ := k.GetIntegerValue("SystemComponent")
			parent, _, _ := k.GetStringValue("ParentKeyName")
			version, _, _ := k.GetStringValue("DisplayVersion")
			publisher, _, _ := k.GetStringValue("Publisher")
			installed, _, _ := k.GetStringValue("InstallDate")
			k.Close()

			name = strings.TrimSpace(name)
			// Pomijamy wpisy techniczne i aktualizacje podpięte pod inne programy.
			if name == "" || sysComp == 1 || parent != "" {
				continue
			}
			key := strings.ToLower(name) + "|" + version
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			sw := Software{Name: truncate(name, 256), Version: truncate(strings.TrimSpace(version), 128), Publisher: truncate(strings.TrimSpace(publisher), 256)}
			if dateRe.MatchString(installed) {
				sw.InstalledOn = installed[:4] + "-" + installed[4:6] + "-" + installed[6:]
			}
			out = append(out, sw)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	if len(out) > 5000 {
		out = out[:5000]
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// collectSecurity zbiera sam status: ochrona w czasie rzeczywistym Defendera. BitLocker wymaga WMI, więc „unknown”.
func collectSecurity() Security {
	disabled, ok := regInt(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", read64)
	return Security{DefenderOn: !ok || disabled == 0, BitLockerStatus: "unknown"}
}
