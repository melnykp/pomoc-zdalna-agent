//go:build windows

package capture

import (
	"fmt"
	"unsafe"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// OpenDuplicatorOn otwiera duplikację monitora na istniejącym urządzeniu D3D11 (dev, ctx), które musi leżeć na karcie
// obsługującej to wyjście (d.AdapterIdx). Urządzenie zostaje własnością wołającego.
func OpenDuplicatorOn(d Display, dev, ctx *com.Object) (*Duplicator, error) {
	f, err := createFactory()
	if err != nil {
		return nil, err
	}
	defer com.Release(f)
	var ad *com.Object
	if err := com.Check("EnumAdapters1", com.Call(f, slotFactoryEnumAdapters1, uintptr(d.AdapterIdx), uintptr(unsafe.Pointer(&ad)))); err != nil {
		return nil, err
	}
	defer com.Release(ad)
	var op *com.Object
	if err := com.Check("EnumOutputs", com.Call(ad, slotAdapterEnumOutputs, uintptr(d.OutputIdx), uintptr(unsafe.Pointer(&op)))); err != nil {
		return nil, err
	}
	defer com.Release(op)
	op1, err := com.QueryInterface(op, &iidOutput1)
	if err != nil {
		return nil, fmt.Errorf("IDXGIOutput1: %w", err)
	}
	defer com.Release(op1)
	var dupl *com.Object
	if h := com.Call(op1, slotOutput1Duplicate, uintptr(unsafe.Pointer(dev)), uintptr(unsafe.Pointer(&dupl))); h.Failed() {
		return nil, fmt.Errorf("DuplicateOutput: %w", h)
	}
	var dd duplDesc
	com.Call(dupl, slotDuplGetDesc, uintptr(unsafe.Pointer(&dd)))
	return &Duplicator{Display: d, device: dev, ctx: ctx, dupl: dupl, w: int(dd.Width), h: int(dd.Height), shared: true}, nil
}

// GPUFrame to klatka pulpitu w pamięci GPU (tekstura BGRA). Ważna do ReleaseTexture.
type GPUFrame struct {
	Tex         *com.Object
	PresentQPC  int64
	Accumulated uint32
	res         *com.Object
}

// AcquireTexture czeka do timeoutMs na nową klatkę i zwraca jej teksturę bez kopiowania do pamięci procesu.
// Po użyciu trzeba wywołać ReleaseTexture. Zwraca ErrTimeout, gdy ekran się nie zmienił.
func (d *Duplicator) AcquireTexture(timeoutMs uint32) (GPUFrame, error) {
	var info frameInfo
	var res *com.Object
	h := com.Call(d.dupl, slotDuplAcquire, uintptr(timeoutMs), uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&res)))
	switch {
	case h == dxgiErrorWaitTimeout:
		return GPUFrame{}, ErrTimeout
	case h == dxgiErrorAccessLost:
		return GPUFrame{}, fmt.Errorf("%w: %v", ErrAccessLost, h)
	case h == eAccessDenied:
		return GPUFrame{}, fmt.Errorf("%w (E_ACCESSDENIED, pulpit bezpieczny?): %v", ErrAccessLost, h)
	case h.Failed():
		return GPUFrame{}, fmt.Errorf("AcquireNextFrame: %w", h)
	}
	d.notePointer(&info)
	if info.LastPresent == 0 { // tylko kursor
		com.Release(res)
		com.Call(d.dupl, slotDuplReleaseFrame)
		return GPUFrame{}, ErrTimeout
	}
	tex, err := com.QueryInterface(res, &iidTexture2D)
	if err != nil {
		com.Release(res)
		com.Call(d.dupl, slotDuplReleaseFrame)
		return GPUFrame{}, err
	}
	return GPUFrame{Tex: tex, PresentQPC: info.LastPresent, Accumulated: info.AccumulatedFrame, res: res}, nil
}

// ReleaseTexture oddaje klatkę systemowi (po zakolejkowaniu wszystkich odczytów z jej tekstury).
func (d *Duplicator) ReleaseTexture(f *GPUFrame) {
	com.Release(f.Tex)
	com.Release(f.res)
	com.Call(d.dupl, slotDuplReleaseFrame)
	*f = GPUFrame{}
}
