package peer

import (
	"encoding/json"
	"sort"
	"sync"
)

// InputMsg to zdarzenie wejścia z widza (kanały danych "ctrl" i "mouse"). Współrzędne są znormalizowane 0..1
// względem kodowanego monitora.
type InputMsg struct {
	T  string  `json:"t"`            // mm, md, mu, wh, kd, ku, release, cfg, ping
	X  float64 `json:"x,omitempty"`  // 0..1
	Y  float64 `json:"y,omitempty"`  // 0..1
	B  int     `json:"b,omitempty"`  // przycisk: 0 lewy, 1 środkowy, 2 prawy, 3 wstecz, 4 dalej
	DX int     `json:"dx,omitempty"` // kółko (jednostki WHEEL_DELTA)
	DY int     `json:"dy,omitempty"`
	C  string  `json:"c,omitempty"`  // KeyboardEvent.code
	TC float64 `json:"tc,omitempty"` // czas klienta (ping)
	// cfg: zmiana monitora i klatek w trakcie sesji (-1 = bez zmian).
	Mon *int `json:"mon,omitempty"`
	FPS *int `json:"fps,omitempty"`
}

// Injector wstrzykuje wejście do systemu. Implementacja produkcyjna to winput.Injector; testy podstawiają atrapę.
type Injector interface {
	Move(nx, ny float64) error
	Button(b int, down bool) error
	Wheel(dx, dy int) error
	Key(code string, down bool) error
}

// Pressed pamięta wciśnięte klawisze i przyciski, żeby po zerwaniu połączenia (albo na żądanie widza) puścić je
// wszystkie: inaczej komputer klienta zostałby np. z wciśniętym Ctrl albo lewym przyciskiem myszy.
type Pressed struct {
	mu      sync.Mutex
	keys    map[string]struct{}
	buttons map[int]struct{}
}

// NewPressed tworzy pusty rejestr.
func NewPressed() *Pressed {
	return &Pressed{keys: map[string]struct{}{}, buttons: map[int]struct{}{}}
}

// Key notuje stan klawisza.
func (p *Pressed) Key(code string, down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if down {
		p.keys[code] = struct{}{}
	} else {
		delete(p.keys, code)
	}
}

// Button notuje stan przycisku myszy.
func (p *Pressed) Button(b int, down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if down {
		p.buttons[b] = struct{}{}
	} else {
		delete(p.buttons, b)
	}
}

// ReleaseAll puszcza wszystko, co jest wciśnięte (klawisze w ustalonym porządku: najpierw zwykłe, modyfikatory na końcu,
// żeby np. puszczenie Shift przed literą nie dało innego znaku), i czyści rejestr. Zwraca liczbę puszczonych.
func (p *Pressed) ReleaseAll(inj Injector) int {
	p.mu.Lock()
	keys := make([]string, 0, len(p.keys))
	for k := range p.keys {
		keys = append(keys, k)
	}
	buttons := make([]int, 0, len(p.buttons))
	for b := range p.buttons {
		buttons = append(buttons, b)
	}
	p.keys = map[string]struct{}{}
	p.buttons = map[int]struct{}{}
	p.mu.Unlock()

	sort.SliceStable(keys, func(i, j int) bool {
		mi, mj := isModifier(keys[i]), isModifier(keys[j])
		if mi != mj {
			return !mi
		}
		return keys[i] < keys[j]
	})
	sort.Ints(buttons)
	n := 0
	if inj != nil {
		for _, b := range buttons {
			if inj.Button(b, false) == nil {
				n++
			}
		}
		for _, k := range keys {
			if inj.Key(k, false) == nil {
				n++
			}
		}
	}
	return n
}

// Count zwraca liczbę wciśniętych klawiszy i przycisków.
func (p *Pressed) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys) + len(p.buttons)
}

func isModifier(code string) bool {
	switch code {
	case "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight", "AltLeft", "AltRight", "MetaLeft", "MetaRight":
		return true
	}
	return false
}

// Apply wykonuje jedno zdarzenie wejścia przez wstrzykiwacz i aktualizuje rejestr wciśniętych. Zdarzenia inne niż
// wejście (ping, cfg, release) zwracają false bez działania.
func Apply(inj Injector, pressed *Pressed, m InputMsg) (handled bool, err error) {
	switch m.T {
	case "mm":
		return true, inj.Move(m.X, m.Y)
	case "md", "mu":
		if m.X != 0 || m.Y != 0 {
			_ = inj.Move(m.X, m.Y)
		}
		down := m.T == "md"
		if err := inj.Button(m.B, down); err != nil {
			return true, err
		}
		pressed.Button(m.B, down)
		return true, nil
	case "wh":
		return true, inj.Wheel(m.DX, m.DY)
	case "kd", "ku":
		down := m.T == "kd"
		if err := inj.Key(m.C, down); err != nil {
			return true, err
		}
		pressed.Key(m.C, down)
		return true, nil
	}
	return false, nil
}

// ParseInput dekoduje zdarzenie z kanału danych; odrzuca ramki większe niż kilkaset bajtów (zdarzenia są malutkie).
func ParseInput(raw []byte) (InputMsg, bool) {
	if len(raw) == 0 || len(raw) > 512 {
		return InputMsg{}, false
	}
	var m InputMsg
	if err := json.Unmarshal(raw, &m); err != nil || m.T == "" {
		return InputMsg{}, false
	}
	return m, true
}
