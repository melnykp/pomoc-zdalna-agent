//go:build windows

package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/peer"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/winput"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/winput/hooktest"
	"github.com/melnykp/pomoc-zdalna-agent/internal/wintoken"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Autotest wejścia na prawdziwym pulpicie: prawdziwy desktop-helper, pion w roli przeglądarki wysyła zdarzenia kanałami danych,
// a globalne haki niskiego poziomu (WH_MOUSE_LL, WH_KEYBOARD_LL, jak w cmd/inputprobe z prototypu) potwierdzają, że SendInput
// DOSZEDŁ do systemu z flagą „injected” i właściwymi wartościami, a nie tylko że handler został wywołany. Test nie klika i nie
// pisze znaków: tylko ruch kursora (kursor wraca na miejsce), kółko +120/−120 (suma zero) oraz same Shift i Ctrl.
// Wymaga RMM_DESKTOP_E2E=1 (przechwytuje ekran i porusza kursorem tego komputera).

// ownTokenLauncher uruchamia pomocnika dokładnie tą samą ścieżką co usługa (startWithToken: CreateProcessAsUser, potoki
// jako stdin/stdout, środowisko użytkownika, winsta0\default, bez okna konsoli), ale z kopią tokenu bieżącego procesu zamiast
// WTSQueryUserToken (ten wymaga konta SYSTEM). Różni się więc od usługi tylko źródłem tokenu.
func ownTokenLauncher(t *testing.T, restrict, minimalEnv bool) func(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
	return func(_ context.Context, exe string, log *slog.Logger) (Process, error) {
		var self windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &self); err != nil {
			return nil, err
		}
		defer self.Close()
		var dup windows.Token
		if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
			return nil, err
		}
		defer dup.Close()
		var session uint32
		_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
		procTok := dup
		if restrict {
			// Ta sama operacja co w produkcji dla tokenu administratora: odjęcie uprawnień (zostaje SeChangeNotifyPrivilege).
			// Ograniczamy token procesu wprost (nie jego kopię): zwykły proces bez SeAssignPrimaryTokenPrivilege może przekazać do
			// CreateProcessAsUser tylko token będący ograniczoną wersją jego własnego; usługa SYSTEM ma to uprawnienie.
			r, err := wintoken.Restrict(self, false)
			if err != nil {
				return nil, err
			}
			defer r.Close()
			procTok = r
		}
		p, err := startWithToken(procTok, dup, minimalEnv, session, exe, log)
		if err != nil && errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("CreateProcessAsUser z kopią własnego tokenu wymaga uprawnień, których tu nie ma: %v", err)
		}
		return p, err
	}
}

type inputViewer struct {
	pc          *webrtc.PeerConnection
	ctrl, mouse *webrtc.DataChannel
	mu          sync.Mutex
	input       *peer.InputStatsMsg
	displays    bool
}

func (v *inputViewer) lastInput() *peer.InputStatsMsg {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.input
}

func (v *inputViewer) gotDisplays() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.displays
}

func connectInputViewer(t *testing.T, eng *Engine, sessionID string) *inputViewer {
	t.Helper()
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			if _, _, err := tr.ReadRTP(); err != nil {
				return
			}
		}
	})
	v := &inputViewer{pc: pc}
	zero := uint16(0)
	unordered := false
	if v.ctrl, err = pc.CreateDataChannel("ctrl", nil); err != nil {
		t.Fatal(err)
	}
	if v.mouse, err = pc.CreateDataChannel("mouse", &webrtc.DataChannelInit{Ordered: &unordered, MaxRetransmits: &zero}); err != nil {
		t.Fatal(err)
	}
	if _, err = pc.CreateDataChannel("cursor", nil); err != nil {
		t.Fatal(err)
	}
	meta, err := pc.CreateDataChannel("meta", nil)
	if err != nil {
		t.Fatal(err)
	}
	meta.OnMessage(func(m webrtc.DataChannelMessage) {
		var head struct {
			T string `json:"t"`
		}
		_ = json.Unmarshal(m.Data, &head)
		switch head.T {
		case "displays":
			v.mu.Lock()
			v.displays = true
			v.mu.Unlock()
		case "input":
			var im peer.InputStatsMsg
			if json.Unmarshal(m.Data, &im) == nil {
				v.mu.Lock()
				v.input = &im
				v.mu.Unlock()
			}
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gather
	sdp := pc.LocalDescription().SDP
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ans, err := eng.Signal(ctx, sessionID, wire.RemoteSignal{SessionID: sessionID, Kind: wire.SignalOffer, SDP: sdp, Fingerprint: peer.Fingerprint(sdp)})
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: ans.SDP}); err != nil {
		t.Fatal(err)
	}
	return v
}

func buildHelperForTest(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), HelperExeName)
	build := exec.Command("go", "build", "-o", exe, "../../cmd/desktop-helper")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("budowanie pomocnika: %v\n%s", err, out)
	}
	return exe
}

var procSetCursorPos = windows.NewLazySystemDLL("user32.dll").NewProc("SetCursorPos")

func TestInputReachesSystemThroughHelper(t *testing.T) {
	if os.Getenv("RMM_DESKTOP_E2E") != "1" {
		t.Skip("ustaw RMM_DESKTOP_E2E=1, test porusza kursorem i przechwytuje ekran tego komputera")
	}
	proc.SetDPIAware() // współrzędne z haków w pikselach fizycznych, tak jak w pomocniku
	displays, err := capture.ListDisplays()
	if err != nil || len(displays) == 0 {
		t.Fatalf("monitory: %v", err)
	}
	d := displays[0]
	left, top, w, h := int(d.Left), int(d.Top), d.Width()&^1, d.Height()&^1

	variants := []struct {
		name   string
		launch func(t *testing.T) func(ctx context.Context, exe string, log *slog.Logger) (Process, error)
	}{
		{"zwykły proces potomny", func(*testing.T) func(context.Context, string, *slog.Logger) (Process, error) { return launchChild }},
		{"CreateProcessAsUser (kopia tokenu, ścieżka usługi)", func(t *testing.T) func(context.Context, string, *slog.Logger) (Process, error) {
			return ownTokenLauncher(t, false, false)
		}},
		{"CreateProcessAsUser (token po odjęciu uprawnień i minimalne środowisko, jak dla wysokiej integralności)", func(t *testing.T) func(context.Context, string, *slog.Logger) (Process, error) {
			return ownTokenLauncher(t, true, true)
		}},
	}
	for i, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			waitForInputDesktop(t)
			exe := buildHelperForTest(t)
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			eng := NewEngine(exe, log)
			eng.Launch = variant.launch(t)
			v := connectInputViewer(t, eng, fmt.Sprintf("input-%d", i))
			t.Cleanup(func() { eng.EndSession(context.Background()) })

			deadline := time.Now().Add(20 * time.Second)
			for !v.gotDisplays() {
				if time.Now().After(deadline) {
					t.Fatal("pomocnik nie zweryfikował widza i nie wysłał listy monitorów")
				}
				time.Sleep(20 * time.Millisecond)
			}

			rec, err := hooktest.Start()
			if err != nil {
				t.Fatalf("haki: %v", err)
			}
			defer rec.Stop()
			cx0, cy0 := winput.CursorPos()
			defer procSetCursorPos.Call(uintptr(cx0), uintptr(cy0))
			time.Sleep(300 * time.Millisecond)

			// 1) Ruch myszy: kanał mouse (bez gwarancji doręczenia, więc ponawiamy do skutku, tak jak robi to widz co klatkę).
			var latencies []time.Duration
			for _, p := range [][2]float64{{0.25, 0.25}, {0.75, 0.25}, {0.5, 0.75}, {0.1, 0.9}} {
				wantX, wantY := winput.NormToPixel(p[0], left, w), winput.NormToPixel(p[1], top, h)
				mark := rec.Mark()
				start := time.Now()
				var got hooktest.Event
				ok := false
				for try := 0; try < 8 && !ok; try++ {
					_ = v.mouse.SendText(fmt.Sprintf(`{"t":"mm","x":%f,"y":%f}`, p[0], p[1]))
					got, ok = rec.Wait(mark, 250*time.Millisecond, func(e hooktest.Event) bool {
						return e.Kind == "move" && absInt(e.X-wantX) <= 1 && absInt(e.Y-wantY) <= 1
					})
				}
				if !ok {
					failOrSkip(t, "ruch do (%.2f,%.2f) = piksel (%d,%d) NIE dotarł do systemu; zdarzenia z haków: %+v", p[0], p[1], wantX, wantY, rec.All())
				}
				if !got.Injected {
					t.Fatalf("zdarzenie bez flagi injected: %+v", got)
				}
				latencies = append(latencies, got.At.Sub(start))
			}
			t.Logf("ruch myszy: viewer → system (hak LL) opóźnienia %v", latencies)

			// 2) Klawisze modyfikujące (nic nie wpisują i niczego nie klikają).
			for _, k := range []struct {
				code     string
				vk       uint32
				scan     uint32
				extended bool
			}{{"ShiftLeft", 0xA0, 0x2A, false}, {"ControlLeft", 0xA2, 0x1D, false}, {"ControlRight", 0xA3, 0x1D, true}} {
				for _, down := range []bool{true, false} {
					kind, typ := "keyup", "ku"
					if down {
						kind, typ = "keydown", "kd"
					}
					mark := rec.Mark()
					if err := v.ctrl.SendText(fmt.Sprintf(`{"t":%q,"c":%q}`, typ, k.code)); err != nil {
						t.Fatal(err)
					}
					e, ok := rec.Wait(mark, 2*time.Second, func(e hooktest.Event) bool { return e.Kind == kind && e.VK == k.vk })
					if !ok {
						failOrSkip(t, "klawisz %s (%s) NIE dotarł do systemu; zdarzenia z haków: %+v", k.code, typ, rec.All())
					}
					if !e.Injected || e.Scan != k.scan || e.Extended != k.extended {
						t.Fatalf("klawisz %s: %+v (oczekiwano scan 0x%X, extended=%v)", k.code, e, k.scan, k.extended)
					}
				}
			}

			// 3) Kółko: +120 i −120 (suma zero).
			for _, dy := range []int{120, -120} {
				mark := rec.Mark()
				if err := v.ctrl.SendText(fmt.Sprintf(`{"t":"wh","dy":%d}`, dy)); err != nil {
					t.Fatal(err)
				}
				if _, ok := rec.Wait(mark, 2*time.Second, func(e hooktest.Event) bool { return e.Kind == "wheel" && e.Wheel == dy }); !ok {
					failOrSkip(t, "kółko %d NIE dotarło do systemu", dy)
				}
			}

			// 4) Komunikat o stanie wejścia, który widz dostaje od komputera, zgadza się z tym, co system naprawdę przyjął.
			var im *peer.InputStatsMsg
			deadline = time.Now().Add(6 * time.Second)
			for time.Now().Before(deadline) {
				if m := v.lastInput(); m != nil && m.Injected >= 4+6+2 {
					im = m
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if im == nil {
				t.Fatalf("komunikat o wejściu nie zgłosił wstrzyknięć: %+v", v.lastInput())
			}
			procJSON, _ := json.Marshal(im.Proc)
			fgJSON, _ := json.Marshal(im.FG)
			t.Logf("stan wejścia z komputera: odebrane ctrl=%d mouse=%d, odrzucone=%d, wstrzyknięte=%d, błędy=%d, rozbieżność kursora=%d, dtls=%s, kanały=%v",
				im.Rx.Ctrl, im.Rx.Mouse, im.Rejected, im.Injected, im.Errors, im.Mismatch, im.DTLS, im.Channels)
			t.Logf("kontekst pomocnika: %s", procJSON)
			t.Logf("okno na pierwszym planie: %s", fgJSON)
			if im.Errors != 0 || im.Rejected != 0 || im.DTLS != "zgodny" || !im.Control {
				t.Fatalf("stan wejścia niezgodny z oczekiwaniem: %+v", im)
			}
			for _, ch := range []string{"ctrl", "mouse", "cursor", "meta"} {
				if !im.Channels[ch] {
					t.Fatalf("kanał %s nieotwarty: %v", ch, im.Channels)
				}
			}
			ctxMap, _ := im.Proc.(map[string]any)
			// Pulpit wątku = wejściowy, o ile w chwili odczytu pulpit wejściowy jest dostępny (komputer zablokowany potrafi przełączyć się
			// na pulpit zabezpieczony między zdarzeniami a odczytem; wtedy zdarzenia już przeszły, a ten odczyt niczego nie dowodzi).
			if ok, _ := ctxMap["input_desktop_ok"].(bool); ok {
				if td, in := ctxMap["thread_desktop"], ctxMap["input_desktop"]; td == "" || td != in {
					t.Fatalf("pulpit wątku wstrzykiwania (%v) powinien być pulpitem wejściowym (%v)", td, in)
				}
			} else {
				t.Logf("w chwili odczytu pulpit wejściowy był niedostępny (pulpit zabezpieczony), pomijam porównanie pulpitów")
			}
			if !strings.EqualFold(fmt.Sprint(ctxMap["window_station"]), "WinSta0") {
				t.Fatalf("stacja okien: %v", ctxMap["window_station"])
			}
			if p, _ := ctxMap["priv"].(string); p != "admin" && p != "integrity" && p != "user" {
				t.Fatalf("kontekst pomocnika nie niesie poziomu uprawnień (priv): %v", ctxMap["priv"])
			}
			if strings.Contains(variant.name, "odjęciu uprawnień") {
				// Wejście działa mimo odjętych uprawnień, a pomocnik widzi (i raportuje) tylko to, co mu zostało.
				pr, _ := ctxMap["privileges"].([]any)
				if len(pr) != 1 || fmt.Sprint(pr[0]) != "SeChangeNotifyPrivilege" {
					t.Fatalf("po odjęciu uprawnień pomocnik powinien mieć tylko SeChangeNotifyPrivilege: %v", pr)
				}
			}
		})
	}
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// waitForInputDesktop czeka (do 3 minut), aż pulpit wejściowy będzie dostępny dla zwykłego procesu użytkownika. Gdy komputer
// jest zablokowany i pokazuje pulpit zabezpieczony (Winlogon: PIN, UAC, Ctrl+Alt+Del), OpenInputDesktop, DuplicateOutput i
// SendInput dostają odmowę dostępu; to nie jest błąd wstrzykiwania, tylko ograniczenie, które ma rozwiązać etap 1b (proces
// SYSTEM na pulpicie Winlogon). Test czeka na odblokowanie albo ekran blokady na zwykłym pulpicie, potem się pomija.
func waitForInputDesktop(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	var last string
	for {
		name, err := winput.InputDesktopName()
		if err == nil {
			if last != "" {
				t.Logf("pulpit wejściowy znów dostępny: %q", name)
			}
			return
		}
		last = err.Error()
		if time.Now().After(deadline) {
			t.Skipf("pulpit wejściowy niedostępny przez 3 minuty (%s): komputer pokazuje pulpit zabezpieczony (blokada/UAC); odblokuj komputer i powtórz", last)
		}
		time.Sleep(2 * time.Second)
	}
}

// failOrSkip kończy test błędem, chyba że w tej chwili pulpit wejściowy jest niedostępny (przełączył się na zabezpieczony w
// trakcie testu): wtedy brak wejścia jest skutkiem stanu komputera, nie wadą wstrzykiwania, i test się pomija z opisem.
func failOrSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	if name, err := winput.InputDesktopName(); err != nil {
		t.Skipf("pulpit wejściowy stał się niedostępny w trakcie testu (%v), pomijam: "+format, append([]any{err}, args...)...)
	} else {
		t.Fatalf("pulpit wejściowy %q dostępny, a wejście nie dotarło: "+format, append([]any{name}, args...)...)
	}
}
