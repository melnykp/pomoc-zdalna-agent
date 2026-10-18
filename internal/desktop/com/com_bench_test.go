//go:build windows

package com_test

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// BenchmarkCallAddRefRelease mierzy koszt jednego wywołania COM z Go bez cgo (syscall.SyscallN przez vtable).
// To jedyny narzut języka względem natywnego pomocnika; kodek i GPU pracują tak samo niezależnie od języka wołającego.
func BenchmarkCallAddRefRelease(b *testing.B) {
	dxgi := windows.NewLazySystemDLL("dxgi.dll")
	create := dxgi.NewProc("CreateDXGIFactory1")
	iid := com.MustGUID(0x770aae78, 0xf26f, 0x4dba, 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87)
	var f *com.Object
	r, _, _ := create.Call(uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&f)))
	if com.HRESULT(uint32(r)).Failed() || f == nil {
		b.Skip("brak DXGI")
	}
	defer com.Release(f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		com.Call(f, 1) // AddRef
		com.Call(f, 2) // Release
	}
}

func TestHRESULT(t *testing.T) {
	if !com.HRESULT(0x80004005).Failed() {
		t.Error("E_FAIL powinno być błędem")
	}
	if com.HRESULT(0).Failed() || com.HRESULT(1).Failed() {
		t.Error("S_OK i S_FALSE nie są błędami")
	}
	if err := com.Check("x", com.HRESULT(0x8000FFFF)); err == nil {
		t.Error("E_UNEXPECTED powinno dać błąd")
	}
}

func TestMustGUIDMatchesWindowsLayout(t *testing.T) {
	g := com.MustGUID(0x770aae78, 0xf26f, 0x4dba, 0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87)
	if g.String() != "{770AAE78-F26F-4DBA-A829-253C83D1B387}" {
		t.Errorf("GUID: %s", g.String())
	}
}
