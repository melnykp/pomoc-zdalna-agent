//go:build windows

// Package proc mierzy zużycie procesora przez bieżący proces (GetProcessTimes) i ustawia świadomość DPI.
package proc

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sample to migawka czasów procesora procesu.
type Sample struct {
	At     time.Time
	Kernel time.Duration
	User   time.Duration
}

// Take odczytuje czasy procesora bieżącego procesu.
func Take() Sample {
	var c, e, k, u windows.Filetime
	h := windows.CurrentProcess()
	_ = windows.GetProcessTimes(h, &c, &e, &k, &u)
	return Sample{At: time.Now(), Kernel: ft(k), User: ft(u)}
}

func ft(f windows.Filetime) time.Duration {
	return time.Duration(int64(f.HighDateTime)<<32|int64(f.LowDateTime)) * 100
}

// Usage to zużycie między dwiema migawkami.
type Usage struct {
	Wall       time.Duration
	CPU        time.Duration
	OfOneCore  float64 // procent jednego rdzenia logicznego (100 = jeden pełny rdzeń)
	OfAllCores float64 // procent całego procesora (wszystkie rdzenie logiczne)
}

// Between liczy zużycie od a do b.
func Between(a, b Sample) Usage {
	wall := b.At.Sub(a.At)
	cpu := (b.Kernel + b.User) - (a.Kernel + a.User)
	u := Usage{Wall: wall, CPU: cpu}
	if wall > 0 {
		u.OfOneCore = 100 * float64(cpu) / float64(wall)
		u.OfAllCores = u.OfOneCore / float64(runtime.NumCPU())
	}
	return u
}

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procSetDpiAwCtx = user32.NewProc("SetProcessDpiAwarenessContext")
	procTimeBeginP  = windows.NewLazySystemDLL("winmm.dll").NewProc("timeBeginPeriod")
)

// RestrictDLLSearch ogranicza domyślne wyszukiwanie bibliotek DLL do System32 i katalogu programu (SetDefaultDllDirectories
// z LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR): ani bieżący katalog, ani PATH nie są przeszukiwane, więc DLL
// podstawiona w katalogu użytkownika nie załaduje się do pomocnika o wysokiej integralności. Wołać na samym początku procesu.
func RestrictDLLSearch() error {
	const searchSystem32, searchApplicationDir = 0x00000800, 0x00000200
	r, _, e := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetDefaultDllDirectories").Call(searchSystem32 | searchApplicationDir)
	if r == 0 {
		return e
	}
	return nil
}

// SetDPIAware włącza tryb per-monitor v2, żeby współrzędne ekranu były w prawdziwych pikselach.
func SetDPIAware() {
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	minusFour := ^uintptr(3)
	procSetDpiAwCtx.Call(minusFour)
}

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	procQPC  = kernel32.NewProc("QueryPerformanceCounter")
	procQPF  = kernel32.NewProc("QueryPerformanceFrequency")
)

// WallMs zwraca czas ścienny z dokładnością do mikrosekund (GetSystemTimePreciseAsFileTime), w ms od epoki Unix.
// Ten sam zegar systemowy czyta przeglądarka (performance.timeOrigin + performance.now()).
func WallMs() float64 {
	var ft windows.Filetime
	windows.GetSystemTimePreciseAsFileTime(&ft)
	ticks := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	return float64(ticks-116444736000000000) / 10000.0
}

// QPC zwraca bieżącą wartość licznika wydajności.
func QPC() int64 {
	var v int64
	procQPC.Call(uintptr(unsafe.Pointer(&v)))
	return v
}

// QPCFreq zwraca częstotliwość licznika wydajności (Hz).
func QPCFreq() int64 {
	var v int64
	procQPF.Call(uintptr(unsafe.Pointer(&v)))
	return v
}

// QPCToWallMs przelicza wartość QPC (z niedalekiej przeszłości) na czas ścienny w ms.
func QPCToWallMs(q int64) float64 {
	nowQ := QPC()
	return WallMs() - float64(nowQ-q)*1000.0/float64(QPCFreq())
}

// HighResTimer prosi system o rozdzielczość zegara 1 ms (dla time.Sleep i tickerów).
func HighResTimer() { procTimeBeginP.Call(1) }
