//go:build windows

package remote

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/peer"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// TestHelperEndToEndOnThisDesktop buduje prawdziwy desktop-helper.exe, uruchamia go przez Engine (jak usługa, tylko bez
// zmiany sesji), a za widza robi pion: oferta → odpowiedź z odciskiem → połączenie → klatki H.264 i komunikaty kursora.
// Przechwytuje ekran tego komputera, więc działa tylko na żądanie: RMM_DESKTOP_E2E=1 (potrzebny pulpit i koder H.264).
func TestHelperEndToEndOnThisDesktop(t *testing.T) {
	if os.Getenv("RMM_DESKTOP_E2E") != "1" {
		t.Skip("ustaw RMM_DESKTOP_E2E=1, test przechwytuje ekran tego komputera")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, HelperExeName)
	build := exec.Command("go", "build", "-o", exe, "../../cmd/desktop-helper")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("budowanie pomocnika: %v\n%s", err, out)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	eng := NewEngine(exe, log)
	eng.Launch = launchChild // bez usługi: proces potomny w tej samej sesji

	// Widz (pion w roli przeglądarki): odbiór wideo H.264 i kanały danych jak w panelu.
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	var packets, bytes atomic.Int64
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if tr.Codec().MimeType != webrtc.MimeTypeH264 {
			t.Errorf("kodek %s, oczekiwano H264", tr.Codec().MimeType)
		}
		for {
			p, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			packets.Add(1)
			bytes.Add(int64(len(p.Payload)))
		}
	})
	ctrl, err := pc.CreateDataChannel("ctrl", nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := pc.CreateDataChannel("cursor", nil)
	if err != nil {
		t.Fatal(err)
	}
	var cursorMsgs, shapes atomic.Int64
	cursor.OnMessage(func(m webrtc.DataChannelMessage) {
		cursorMsgs.Add(1)
		if strings.Contains(string(m.Data), `"shape"`) {
			shapes.Add(1)
		}
	})
	meta, err := pc.CreateDataChannel("meta", nil)
	if err != nil {
		t.Fatal(err)
	}
	var pongs, frameMeta, pathMsgs atomic.Int64
	var degradedSeen atomic.Bool
	meta.OnMessage(func(m webrtc.DataChannelMessage) {
		var v struct {
			T        string `json:"t"`
			Path     string `json:"path"`
			Degraded bool   `json:"degraded"`
		}
		_ = json.Unmarshal(m.Data, &v)
		switch v.T {
		case "path":
			pathMsgs.Add(1)
			if v.Degraded || v.Path == "" {
				degradedSeen.Store(true)
			}
		case "pong":
			pongs.Add(1)
		case "f":
			frameMeta.Add(1)
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	offerSDP := pc.LocalDescription().SDP
	viewerFP := peer.Fingerprint(offerSDP)
	if viewerFP == "" {
		t.Fatalf("oferta pion bez dokładnie jednego odcisku sha-256:\n%s", offerSDP)
	}
	// Przypięty inny odcisk niż w ofercie: pomocnik odmawia, zanim cokolwiek zacznie.
	wrongFP := "53:4C:B1:53:D5:BF:F7:0C:6B:D2:27:CB:33:97:67:0C:BD:52:EB:BF:AA:E5:6B:A3:85:1F:6F:9E:2A:89:46:C4"
	if _, err := eng.Signal(ctx, "e2e-zly", wire.RemoteSignal{SessionID: "e2e-zly", Kind: wire.SignalOffer, SDP: offerSDP, Fingerprint: wrongFP}); err == nil || !strings.Contains(err.Error(), "odcisk") {
		t.Fatalf("oferta z obcym odciskiem powinna zostać odrzucona, a jest: %v", err)
	}
	t0 := time.Now()
	ans, err := eng.Signal(ctx, "e2e", wire.RemoteSignal{SessionID: "e2e", Kind: wire.SignalOffer, SDP: offerSDP, Fingerprint: viewerFP})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("odpowiedź pomocnika po %s, odcisk DTLS %s", time.Since(t0).Round(time.Millisecond), ans.Fingerprint)
	if len(ans.Fingerprint) != 95 {
		t.Fatalf("zły odcisk %q", ans.Fingerprint)
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: ans.SDP}); err != nil {
		t.Fatal(err)
	}

	waitCond := func(what string, d time.Duration, cond func() bool) {
		deadline := time.Now().Add(d)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("nie doczekano: %s", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitCond("połączenie zgłoszone usłudze", 20*time.Second, func() bool { ok, _ := eng.Connected(ctx); return ok })
	t.Logf("połączono po %s", time.Since(t0).Round(time.Millisecond))
	waitCond("pakiety RTP wideo", 15*time.Second, func() bool { return packets.Load() > 50 })
	waitCond("kanał sterowania otwarty", 5*time.Second, func() bool { return ctrl.ReadyState() == webrtc.DataChannelStateOpen })
	_ = ctrl.SendText(`{"t":"ping","tc":1}`)
	waitCond("pong", 5*time.Second, func() bool { return pongs.Load() >= 1 })
	// Widz dostaje w kanale meta ścieżkę przechwytywania; na zdrowym komputerze to nie jest tryb awaryjny.
	waitCond("komunikat o ścieżce", 10*time.Second, func() bool { return pathMsgs.Load() >= 1 })
	if degradedSeen.Load() {
		t.Fatal("widz dostał tryb awaryjny na zdrowym komputerze")
	}
	// Przełączenie na 60 kl./s w trakcie sesji: silnik startuje od nowa, strumień ma płynąć dalej (na nieruchomym ekranie to klatka kluczowa i klatki podtrzymujące, stąd mały próg).
	before := packets.Load()
	_ = ctrl.SendText(`{"t":"cfg","fps":60}`)
	waitCond("strumień po zmianie klatek", 10*time.Second, func() bool { return packets.Load() > before+10 })
	// Ruch kursora (bez klikania): położenie wraca kanałem cursor.
	_ = ctrl.SendText(`{"t":"mm","x":0.5,"y":0.5}`)
	time.Sleep(300 * time.Millisecond)
	_ = ctrl.SendText(`{"t":"mm","x":0.52,"y":0.5}`)
	waitCond("komunikaty kursora", 5*time.Second, func() bool { return cursorMsgs.Load() >= 1 })
	time.Sleep(2 * time.Second)
	t.Logf("po %s: pakietów RTP %d (%d kB), metadanych klatek %d, komunikatów kursora %d (kształtów %d)", time.Since(t0).Round(time.Millisecond),
		packets.Load(), bytes.Load()/1000, frameMeta.Load(), cursorMsgs.Load(), shapes.Load())

	// Zerwanie od strony widza: pomocnik zgłasza rozłączenie ze statystykami i kończy się.
	_ = pc.Close()
	waitCond("rozłączenie", 15*time.Second, func() bool { ok, _ := eng.Connected(ctx); return !ok })
	st := eng.EndSession(ctx)
	if st == nil || st.Frames == 0 || st.BytesOut == 0 || st.DurationMs == 0 {
		t.Fatalf("statystyki sesji: %+v", st)
	}
	t.Logf("statystyki: %+v", *st)
}
