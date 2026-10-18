//go:build windows

// Package com to minimalna warstwa wywołań COM z czystego Go (bez cgo): obiekt COM to wskaźnik na wskaźnik
// na tablicę funkcji (vtable), a metodę woła się po numerze slotu przez syscall.SyscallN.
package com

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GUID to identyfikator COM (ten sam układ w pamięci co GUID z Win32).
type GUID = windows.GUID

// MustGUID buduje GUID ze składowych tak, jak w nagłówkach SDK (DEFINE_GUID).
func MustGUID(d1 uint32, d2, d3 uint16, d4 ...byte) GUID {
	g := GUID{Data1: d1, Data2: d2, Data3: d3}
	copy(g.Data4[:], d4)
	return g
}

// HRESULT to kod wyniku COM; ujemny (bit 31) oznacza błąd.
type HRESULT uint32

func (h HRESULT) Failed() bool { return int32(h) < 0 }

func (h HRESULT) Error() string { return fmt.Sprintf("HRESULT 0x%08X", uint32(h)) }

// Check zwraca błąd opisujący nieudane wywołanie albo nil.
func Check(what string, h HRESULT) error {
	if h.Failed() {
		return fmt.Errorf("%s: %w", what, h)
	}
	return nil
}

// Object to układ pamięci każdego obiektu COM: pierwsze pole to wskaźnik na vtable.
type Object struct {
	vtbl *[512]uintptr
}

// Call woła metodę o numerze slotu idx na obiekcie self. uintptrescapes zatrzymuje wskaźniki zamienione na uintptr
// w argumentach (zmienne wyjściowe nie mogą się przesunąć przy rozroście stosu).
//
//go:uintptrescapes
func Call(self *Object, idx int, args ...uintptr) HRESULT {
	fn := self.vtbl[idx]
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, uintptr(unsafe.Pointer(self)))
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(fn, all...)
	return HRESULT(uint32(r))
}

// Release zwalnia referencję (slot 2 IUnknown). Nil jest dozwolony.
func Release(o *Object) {
	if o != nil {
		Call(o, 2)
	}
}

// ReleaseCount zwalnia referencję i zwraca pozostałą liczbę referencji (0 = obiekt zniszczony). Do diagnozowania wycieków.
func ReleaseCount(o *Object) uint32 {
	if o == nil {
		return 0
	}
	return uint32(Call(o, 2))
}

// QueryInterface pyta obiekt o inny interfejs (slot 0). Zwraca nil z błędem, gdy nieobsługiwany.
func QueryInterface(o *Object, iid *GUID) (*Object, error) {
	var out *Object
	h := Call(o, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if h.Failed() {
		return nil, fmt.Errorf("QueryInterface: %w", h)
	}
	return out, nil
}

var (
	ole32            = windows.NewLazySystemDLL("ole32.dll")
	procCoInitEx     = ole32.NewProc("CoInitializeEx")
	procCoUninit     = ole32.NewProc("CoUninitialize")
	procCoTaskMemFre = ole32.NewProc("CoTaskMemFree")
)

const coinitMultithreaded = 0x0

// InitMTA wchodzi w wielowątkowe mieszkanie COM dla bieżącego wątku systemowego (wywołaj po runtime.LockOSThread).
// S_FALSE (już zainicjowany) jest traktowane jako sukces.
func InitMTA() error {
	r, _, _ := procCoInitEx.Call(0, coinitMultithreaded)
	h := HRESULT(uint32(r))
	if h.Failed() {
		return Check("CoInitializeEx", h)
	}
	return nil
}

// Uninit kończy mieszkanie COM bieżącego wątku.
func Uninit() { procCoUninit.Call() }

// TaskMemFree zwalnia pamięć przydzieloną przez COM (CoTaskMemAlloc).
func TaskMemFree(p unsafe.Pointer) {
	if p != nil {
		procCoTaskMemFre.Call(uintptr(p))
	}
}

// BoolToUintptr zamienia bool na wartość BOOL.
func BoolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}
