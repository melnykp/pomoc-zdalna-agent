//go:build windows

package capture

import (
	"unsafe"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

// subresourceData to D3D11_SUBRESOURCE_DATA.
type subresourceData struct {
	Mem        unsafe.Pointer
	Pitch      uint32
	SlicePitch uint32
}

// UploadBGRA tworzy teksturę BGRA (DEFAULT, do użycia jako wejście procesora wideo) z pikseli w pamięci procesu.
// Służy do pierwszej klatki na ścieżce GPU, gdy ekran stoi i DXGI nie oddaje żadnej tekstury (zrzut GDI).
func UploadBGRA(dev *com.Object, pix []byte, stride, w, h int) (*com.Object, error) {
	if len(pix) < stride*h || stride < w*4 {
		return nil, com.Check("UploadBGRA", com.HRESULT(0x80070057)) // E_INVALIDARG
	}
	desc := texDesc{
		Width: uint32(w), Height: uint32(h), MipLevels: 1, ArraySize: 1, Format: 87, /*B8G8R8A8_UNORM*/
		SampleCount: 1, Usage: 0 /*DEFAULT*/, BindFlags: 0x8 | 0x20, /*RENDER_TARGET | SHADER_RESOURCE, jak tekstura duplikacji*/
	}
	init := subresourceData{Mem: unsafe.Pointer(&pix[0]), Pitch: uint32(stride)}
	var tex *com.Object
	if err := com.Check("CreateTexture2D(upload)", com.Call(dev, slotDeviceCreateTexture2, uintptr(unsafe.Pointer(&desc)), uintptr(unsafe.Pointer(&init)), uintptr(unsafe.Pointer(&tex)))); err != nil {
		return nil, err
	}
	return tex, nil
}
