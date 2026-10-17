//go:build windows

package metrics

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes = kernel32.NewProc("GetSystemTimes")
	procGlobalMemory   = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64 = kernel32.NewProc("GetTickCount64")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// readCPU: czas kernela z GetSystemTimes zawiera czas bezczynności.
func readCPU() (cpuTimes, bool) {
	var idle, kernel, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return cpuTimes{}, false
	}
	return cpuTimes{idle: filetimeToUint64(idle), total: filetimeToUint64(kernel) + filetimeToUint64(user)}, true
}

func readMemory() (usedMB, totalMB int64) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemory.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0
	}
	const mb = 1 << 20
	return int64((m.TotalPhys - m.AvailPhys) / mb), int64(m.TotalPhys / mb)
}

func readUptime() int64 {
	ms, _, _ := procGetTickCount64.Call()
	return int64(ms / 1000)
}

var (
	wtsapi32                       = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory              = wtsapi32.NewProc("WTSFreeMemory")
)

// wtsUserName to klasa informacji WTS_INFO_CLASS::WTSUserName.
const wtsUserName = 5

// readLoggedUser zwraca użytkownika sesji konsoli. Usługa działa jako SYSTEM, więc bieżący użytkownik
// procesu nic nie mówi; pytamy menedżera sesji terminalowych.
func readLoggedUser() string {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return ""
	}
	var buf *uint16
	var n uint32
	r, _, _ := procWTSQuerySessionInformation.Call(0, uintptr(session), wtsUserName, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}
