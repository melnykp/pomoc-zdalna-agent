//go:build windows

// Package hooktest instaluje globalne haki niskiego poziomu (WH_MOUSE_LL, WH_KEYBOARD_LL) i zapisuje zdarzenia wejścia, które
// system naprawdę przyjął do kolejki (z flagą „injected”). Służy WYŁĄCZNIE testom: potwierdza, że SendInput dotarł do
// systemu, a nie tylko że handler pomocnika został wywołany. Nie jest importowany przez żaden program produkcyjny (haki
// klawiatury na komputerze klienta byłyby nie do przyjęcia), a zdarzenia spoza testu są odrzucane już w haku (nie są zapisywane).
package hooktest

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procSetHookEx     = user32.NewProc("SetWindowsHookExW")
	procUnhookEx      = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHook  = user32.NewProc("CallNextHookEx")
	procGetMessage    = user32.NewProc("GetMessageW")
	procPostThreadMsg = user32.NewProc("PostThreadMessageW")
	procGetModule     = kernel32.NewProc("GetModuleHandleW")
)

const (
	whKeyboardLL = 13
	whMouseLL    = 14
	wmQuit       = 0x0012
	wmMouseMove  = 0x0200
	wmMouseWheel = 0x020A
	wmKeyDown    = 0x0100
	wmKeyUp      = 0x0101
	wmSysKeyDown = 0x0104
	wmSysKeyUp   = 0x0105
)

type msllhook struct {
	X, Y      int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	Extra     uintptr
}

type kbdllhook struct {
	VK, Scan, Flags, Time uint32
	Extra                 uintptr
}

// Event to jedno zdarzenie wejścia widziane przez system.
type Event struct {
	Kind     string // "move", "wheel", "keydown", "keyup"
	X, Y     int
	Wheel    int // znak i wartość w jednostkach WHEEL_DELTA
	VK, Scan uint32
	Extended bool
	Injected bool // system oznaczył zdarzenie jako wstrzyknięte (LLMHF_INJECTED / LLKHF_INJECTED)
	At       time.Time
}

// Recorder zbiera zdarzenia z haków. Używać jednego naraz.
type Recorder struct {
	mu     sync.Mutex
	events []Event
	ch     chan Event
	tid    uint32
	done   chan struct{}
	mouse  uintptr
	kbd    uintptr
}

// current to nagrywarka, do której trafiają zdarzenia z procedur haków (callbacki systemowe nie mają kontekstu).
var (
	curMu sync.Mutex
	cur   *Recorder
)

func (r *Recorder) push(e Event) {
	e.At = time.Now()
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	select {
	case r.ch <- e:
	default:
	}
}

func mouseProc(nCode int32, wParam, lParam uintptr) uintptr {
	if nCode >= 0 {
		h := (*msllhook)(*(*unsafe.Pointer)(unsafe.Pointer(&lParam))) // lParam to adres struktury systemowej
		curMu.Lock()
		r := cur
		curMu.Unlock()
		if r != nil && h.Flags&1 != 0 { // tylko wstrzyknięte
			switch wParam {
			case wmMouseMove:
				r.push(Event{Kind: "move", X: int(h.X), Y: int(h.Y), Injected: true})
			case wmMouseWheel:
				r.push(Event{Kind: "wheel", X: int(h.X), Y: int(h.Y), Wheel: int(int16(h.MouseData >> 16)), Injected: true})
			}
		}
	}
	r, _, _ := procCallNextHook.Call(0, uintptr(nCode), wParam, lParam)
	return r
}

func kbdProc(nCode int32, wParam, lParam uintptr) uintptr {
	if nCode >= 0 {
		h := (*kbdllhook)(*(*unsafe.Pointer)(unsafe.Pointer(&lParam)))
		curMu.Lock()
		r := cur
		curMu.Unlock()
		if r != nil && h.Flags&0x10 != 0 { // tylko wstrzyknięte
			kind := "keydown"
			if wParam == wmKeyUp || wParam == wmSysKeyUp {
				kind = "keyup"
			}
			r.push(Event{Kind: kind, VK: h.VK, Scan: h.Scan, Extended: h.Flags&1 != 0, Injected: true})
		}
	}
	r, _, _ := procCallNextHook.Call(0, uintptr(nCode), wParam, lParam)
	return r
}

// Start instaluje haki na własnym wątku z pętlą komunikatów (haki LL tego wymagają, inaczej system wstrzymuje wejście).
func Start() (*Recorder, error) {
	r := &Recorder{ch: make(chan Event, 1024), done: make(chan struct{})}
	curMu.Lock()
	if cur != nil {
		curMu.Unlock()
		return nil, fmt.Errorf("hooktest: nagrywarka już działa")
	}
	cur = r
	curMu.Unlock()
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer close(r.done)
		r.tid = windows.GetCurrentThreadId()
		mod, _, _ := procGetModule.Call(0)
		mh, _, e1 := procSetHookEx.Call(whMouseLL, syscall.NewCallback(mouseProc), mod, 0)
		kh, _, e2 := procSetHookEx.Call(whKeyboardLL, syscall.NewCallback(kbdProc), mod, 0)
		if mh == 0 || kh == 0 {
			ready <- fmt.Errorf("SetWindowsHookEx: mysz=%v klawiatura=%v", e1, e2)
			return
		}
		r.mouse, r.kbd = mh, kh
		ready <- nil
		var msg [8]uintptr // MSG
		for {
			ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
			if int32(ret) <= 0 { // WM_QUIT albo błąd
				break
			}
		}
		procUnhookEx.Call(mh)
		procUnhookEx.Call(kh)
	}()
	if err := <-ready; err != nil {
		curMu.Lock()
		cur = nil
		curMu.Unlock()
		return nil, err
	}
	return r, nil
}

// Events zwraca kanał nowych zdarzeń (przepełnienie gubi najnowsze).
func (r *Recorder) Events() <-chan Event { return r.ch }

// All zwraca wszystkie zapisane dotąd zdarzenia.
func (r *Recorder) All() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// Wait czeka do d na zdarzenie spełniające warunek (przegląda też już zapisane po indeksie from).
func (r *Recorder) Wait(from int, d time.Duration, want func(Event) bool) (Event, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for i := from; i < len(r.events); i++ {
			if want(r.events[i]) {
				e := r.events[i]
				r.mu.Unlock()
				return e, true
			}
		}
		r.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return Event{}, false
}

// Mark zwraca indeks, od którego Wait ma przeglądać nowe zdarzenia.
func (r *Recorder) Mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// Stop zdejmuje haki i kończy wątek.
func (r *Recorder) Stop() {
	procPostThreadMsg.Call(uintptr(r.tid), wmQuit, 0, 0)
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
	}
	curMu.Lock()
	if cur == r {
		cur = nil
	}
	curMu.Unlock()
}
