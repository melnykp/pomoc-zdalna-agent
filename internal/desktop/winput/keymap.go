// Package winput wstrzykuje mysz i klawiaturę do Windows przez SendInput. Tablice i przeliczenia współrzędnych
// (bez wywołań systemowych) są w plikach bez znacznika platformy, żeby dało się je testować wszędzie.
package winput

// Scan opisuje klawisz fizyczny: kod skanowania zestawu 1 i znacznik prefiksu E0.
type Scan struct {
	Code     uint16
	Extended bool
}

// scanByCode mapuje KeyboardEvent.code (położenie klawisza, nie znak) na kod skanowania.
// Wstrzykiwanie po kodzie skanowania oddaje układ klawiatury maszyny zdalnej, tak jak fizyczny klawisz.
var scanByCode = map[string]Scan{
	"Escape": {0x01, false}, "Digit1": {0x02, false}, "Digit2": {0x03, false}, "Digit3": {0x04, false},
	"Digit4": {0x05, false}, "Digit5": {0x06, false}, "Digit6": {0x07, false}, "Digit7": {0x08, false},
	"Digit8": {0x09, false}, "Digit9": {0x0A, false}, "Digit0": {0x0B, false}, "Minus": {0x0C, false},
	"Equal": {0x0D, false}, "Backspace": {0x0E, false}, "Tab": {0x0F, false},
	"KeyQ": {0x10, false}, "KeyW": {0x11, false}, "KeyE": {0x12, false}, "KeyR": {0x13, false},
	"KeyT": {0x14, false}, "KeyY": {0x15, false}, "KeyU": {0x16, false}, "KeyI": {0x17, false},
	"KeyO": {0x18, false}, "KeyP": {0x19, false}, "BracketLeft": {0x1A, false}, "BracketRight": {0x1B, false},
	"Enter": {0x1C, false}, "ControlLeft": {0x1D, false},
	"KeyA": {0x1E, false}, "KeyS": {0x1F, false}, "KeyD": {0x20, false}, "KeyF": {0x21, false},
	"KeyG": {0x22, false}, "KeyH": {0x23, false}, "KeyJ": {0x24, false}, "KeyK": {0x25, false},
	"KeyL": {0x26, false}, "Semicolon": {0x27, false}, "Quote": {0x28, false}, "Backquote": {0x29, false},
	"ShiftLeft": {0x2A, false}, "Backslash": {0x2B, false},
	"KeyZ": {0x2C, false}, "KeyX": {0x2D, false}, "KeyC": {0x2E, false}, "KeyV": {0x2F, false},
	"KeyB": {0x30, false}, "KeyN": {0x31, false}, "KeyM": {0x32, false}, "Comma": {0x33, false},
	"Period": {0x34, false}, "Slash": {0x35, false}, "ShiftRight": {0x36, false},
	"NumpadMultiply": {0x37, false}, "AltLeft": {0x38, false}, "Space": {0x39, false}, "CapsLock": {0x3A, false},
	"F1": {0x3B, false}, "F2": {0x3C, false}, "F3": {0x3D, false}, "F4": {0x3E, false}, "F5": {0x3F, false},
	"F6": {0x40, false}, "F7": {0x41, false}, "F8": {0x42, false}, "F9": {0x43, false}, "F10": {0x44, false},
	"NumLock": {0x45, false}, "ScrollLock": {0x46, false},
	"Numpad7": {0x47, false}, "Numpad8": {0x48, false}, "Numpad9": {0x49, false}, "NumpadSubtract": {0x4A, false},
	"Numpad4": {0x4B, false}, "Numpad5": {0x4C, false}, "Numpad6": {0x4D, false}, "NumpadAdd": {0x4E, false},
	"Numpad1": {0x4F, false}, "Numpad2": {0x50, false}, "Numpad3": {0x51, false}, "Numpad0": {0x52, false},
	"NumpadDecimal": {0x53, false}, "IntlBackslash": {0x56, false}, "F11": {0x57, false}, "F12": {0x58, false},

	"NumpadEnter": {0x1C, true}, "ControlRight": {0x1D, true}, "NumpadDivide": {0x35, true},
	"PrintScreen": {0x37, true}, "AltRight": {0x38, true}, "Home": {0x47, true}, "ArrowUp": {0x48, true},
	"PageUp": {0x49, true}, "ArrowLeft": {0x4B, true}, "ArrowRight": {0x4D, true}, "End": {0x4F, true},
	"ArrowDown": {0x50, true}, "PageDown": {0x51, true}, "Insert": {0x52, true}, "Delete": {0x53, true},
	"MetaLeft": {0x5B, true}, "MetaRight": {0x5C, true}, "ContextMenu": {0x5D, true},
}

// LookupScan zwraca kod skanowania dla KeyboardEvent.code.
func LookupScan(code string) (Scan, bool) {
	s, ok := scanByCode[code]
	return s, ok
}

// AbsCoord zamienia piksel (px) w obrębie osi pulpitu wirtualnego o początku origin i długości size
// na współrzędną bezwzględną SendInput 0..65535 (MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK).
func AbsCoord(px, origin, size int) int {
	if size <= 1 {
		return 0
	}
	rel := px - origin
	if rel < 0 {
		rel = 0
	}
	if rel > size-1 {
		rel = size - 1
	}
	// Środek piksela, żeby zaokrąglenie po stronie systemu trafiło w ten sam piksel.
	return (rel*65536 + 32768) / size
}

// NormToPixel zamienia współrzędną znormalizowaną 0..1 w obrębie monitora o początku origin i rozmiarze size na piksel pulpitu.
func NormToPixel(n float64, origin, size int) int {
	if n < 0 {
		n = 0
	}
	if n > 1 {
		n = 1
	}
	p := int(n * float64(size))
	if p > size-1 {
		p = size - 1
	}
	return origin + p
}
