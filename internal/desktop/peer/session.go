//go:build windows

package peer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/capture"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/engine"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Stany zgłaszane przez OnState.
const (
	StateConnected    = "connected"
	StateDisconnected = "disconnected"
	StateFailed       = "failed"
)

// Nazwy kanałów danych tworzonych przez widza.
const (
	chanCtrl   = "ctrl"   // wejście z gwarancją doręczenia: przyciski, klawisze, cfg, release, ping
	chanMouse  = "mouse"  // ruch myszy bez gwarancji (liczy się tylko ostatnie położenie)
	chanCursor = "cursor" // kursor do widza: położenie i kształt
	chanMeta   = "meta"   // metadane klatek do pomiaru opóźnienia (opcjonalne)
)

// Options konfiguruje sesję.
type Options struct {
	ICEServers []wire.ICEServer
	Engine     *engine.Engine
	// Injector wstrzykuje wejście; nil wyłącza sterowanie (tylko podgląd).
	Injector Injector
	Log      *slog.Logger
	// OnState dostaje connected raz, a potem disconnected albo failed dokładnie raz, ze statystykami sesji.
	OnState func(state string, stats wire.RemoteStats)
	// OnCandidate dostaje kandydatów ICE zebranych po odpowiedzi (trickle); może być nil.
	OnCandidate func(candidate, sdpMid string)
	// OnConfig dostaje żądanie zmiany monitora lub klatek z widza (po zastosowaniu w silniku); może być nil.
	OnConfig func(mon, fps *int)
	// Displays to lista monitorów wysyłana widzowi kanałem "meta" po jego otwarciu (do wyboru monitora).
	Displays []DisplayInfo
	// RemoteFingerprint to odcisk DTLS widza przypięty przez serwer do sesji (z komunikatu start). Oferta z innym
	// odciskiem jest odrzucana, a po połączeniu certyfikat zdalny musi dać ten sam odcisk. Pusty = bez przypięcia
	// (tylko testy i tryb rozwojowy; oferta nadal musi nieść dokładnie jeden odcisk sha-256).
	RemoteFingerprint string
}

// DisplayInfo opisuje monitor dla widza.
type DisplayInfo struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Primary bool   `json:"primary"`
}

// Session to jedno połączenie z jednym widzem.
type Session struct {
	o      Options
	log    *slog.Logger
	pc     *webrtc.PeerConnection
	track  *webrtc.TrackLocalStaticRTP
	pay    *codecs.H264Payloader
	seq    rtp.Sequencer
	pressd *Pressed

	mu          sync.Mutex
	cursor      *webrtc.DataChannel
	meta        *webrtc.DataChannel
	started     bool
	ended       bool
	cancel      context.CancelFunc
	engineDone  chan struct{}
	connectedAt time.Time
	lastPtr     capture.Pointer
	sentShape   *capture.PointerShape
	// remoteFP to odcisk z oferty widza; verified: 0 = jeszcze nie sprawdzono, 1 = zgodny, -1 = niezgodny.
	remoteFP string
	verified int
	inputOff atomic.Bool

	// Punkty podmiany w testach: certyfikat zdalny, uruchomienie silnika, odstęp prób weryfikacji.
	remoteCert func() []byte
	runEngine  func(ctx context.Context) error
	verifyPoll time.Duration
	rejectLog  *rateLimiter // odrzucone wejście: 1 wpis na sekundę
	sendLog    *rateLimiter // błędy SendInput: 1 wpis na sekundę

	bytesOut atomic.Int64
	bytesIn  atomic.Int64
	frames   atomic.Int64
}

func newAPI(servers []wire.ICEServer) (*webrtc.API, error) {
	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return nil, err
	}
	se := webrtc.SettingEngine{}
	// Przeglądarka ukrywa adresy lokalne za nazwami mDNS; bez TURN połączenie w sieci lokalnej wymaga ich rozwiązania.
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryOnly)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	// Pętla zwrotna tylko bez serwerów ICE (test na jednym komputerze); z TURN kandydat loopback jest zbędnym szumem.
	se.SetIncludeLoopbackCandidate(len(servers) == 0)
	return webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se)), nil
}

func iceConfig(servers []wire.ICEServer) webrtc.Configuration {
	cfg := webrtc.Configuration{}
	for _, s := range servers {
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	return cfg
}

// New tworzy sesję gotową na ofertę widza.
func New(o Options) (*Session, error) {
	if o.Engine == nil {
		return nil, errors.New("peer: brak silnika")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	api, err := newAPI(o.ICEServers)
	if err != nil {
		return nil, err
	}
	pc, err := api.NewPeerConnection(iceConfig(o.ICEServers))
	if err != nil {
		return nil, err
	}
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeH264, ClockRate: 90000,
		SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
	}, "video", "desktop")
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	s := &Session{o: o, log: o.Log, pc: pc, track: track, pay: &codecs.H264Payloader{}, seq: rtp.NewRandomSequencer(), pressd: NewPressed()}
	s.remoteCert = s.pionRemoteCert
	s.runEngine = func(ctx context.Context) error { return s.o.Engine.Run(ctx, s) }
	s.verifyPoll = defaultVerifyPoll
	s.rejectLog = newRateLimiter(verifyRejectLogEach)
	s.sendLog = newRateLimiter(time.Second)
	if o.Injector == nil {
		s.log.Info("sesja tylko do podglądu: wstrzykiwanie wejścia wyłączone")
	} else {
		s.log.Info("wstrzykiwanie wejścia włączone")
	}
	o.Engine.SetOnPath(func(pi engine.PathInfo) {
		s.mu.Lock()
		dc := s.meta
		s.mu.Unlock()
		if dc != nil {
			s.sendJSON(dc, NewPathMsg(pi.Path, pi.Degraded, pi.Reason))
		}
	})
	sender, err := pc.AddTrack(track)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	go func() { // RTCP od widza: PLI/FIR to prośba o klatkę kluczową
		for {
			pkts, _, err := sender.ReadRTCP()
			if err != nil {
				return
			}
			for _, p := range pkts {
				switch p.(type) {
				case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
					s.o.Engine.RequestKeyFrame()
				}
			}
		}
	}()
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		label := dc.Label()
		// Handlery rejestrujemy ZAWSZE: certyfikat DTLS widza bywa dostępny chwilę po otwarciu kanału, a handler
		// niezarejestrowany w tej chwili nie wróciłby już nigdy (wideo płynęłoby, a wejście, kursor i monitory nie).
		// Bramka weryfikacji stoi w chwili użycia.
		dc.OnOpen(func() { s.log.Info("kanał danych otwarty", "channel", label) })
		switch label {
		case chanCtrl, chanMouse:
			dc.OnMessage(func(m webrtc.DataChannelMessage) { s.onChannelMessage(label, m.Data) })
		case chanCursor:
			dc.OnOpen(func() {
				s.log.Info("kanał danych otwarty", "channel", label)
				s.whenVerified(label, func() {
					s.mu.Lock()
					s.cursor = dc
					last := s.lastPtr
					s.mu.Unlock()
					// Nowy kanał dostaje od razu ostatni znany kształt i położenie.
					if last.Shape != nil || last.Moved {
						s.sendPointer(last, true)
					}
				})
			})
		case chanMeta:
			dc.OnOpen(func() {
				s.log.Info("kanał danych otwarty", "channel", label)
				s.whenVerified(label, func() {
					s.mu.Lock()
					s.meta = dc
					s.mu.Unlock()
					cfg := s.o.Engine.Config()
					s.sendJSON(dc, map[string]any{"t": "displays", "list": s.o.Displays, "monitor": cfg.Monitor, "fps": cfg.FPS})
					// Widz, który dołączył po starcie silnika, od razu dowiaduje się, na jakiej ścieżce pracujemy.
					if pi := s.o.Engine.Path(); pi.Path != "" {
						s.sendJSON(dc, NewPathMsg(pi.Path, pi.Degraded, pi.Reason))
					}
				})
			})
		}
	})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil || s.o.OnCandidate == nil {
			return
		}
		init := c.ToJSON()
		mid := ""
		if init.SDPMid != nil {
			mid = *init.SDPMid
		}
		s.o.OnCandidate(init.Candidate, mid)
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		s.log.Info("połączenie WebRTC", "state", st.String())
		switch st {
		case webrtc.PeerConnectionStateConnected:
			// Certyfikat zdalny bywa dostępny chwilę po zmianie stanu; kilka prób, zanim uznamy brak za błąd.
			go s.verifyThenStart()
		case webrtc.PeerConnectionStateFailed:
			s.end(StateFailed)
		case webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			s.end(StateDisconnected)
		}
	})
	return s, nil
}

// Answer przyjmuje ofertę widza i zwraca odpowiedź po zebraniu kandydatów ICE (do 5 s) razem z odciskiem DTLS pomocnika.
func (s *Session) Answer(offerSDP string) (answer, fingerprint string, err error) {
	// Oferta musi nieść dokładnie jeden odcisk sha-256 i, gdy serwer przypiął odcisk widza do sesji, właśnie ten.
	remoteFP := Fingerprint(offerSDP)
	if remoteFP == "" {
		return "", "", errors.New("oferta SDP bez dokładnie jednego odcisku DTLS sha-256")
	}
	if s.o.RemoteFingerprint != "" && !strings.EqualFold(s.o.RemoteFingerprint, remoteFP) {
		return "", "", errors.New("odcisk DTLS oferty nie zgadza się z odciskiem przypiętym do sesji")
	}
	s.mu.Lock()
	s.remoteFP = remoteFP
	s.mu.Unlock()
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offerSDP}); err != nil {
		return "", "", fmt.Errorf("oferta SDP: %w", err)
	}
	ans, err := s.pc.CreateAnswer(nil)
	if err != nil {
		return "", "", err
	}
	gather := webrtc.GatheringCompletePromise(s.pc)
	if err := s.pc.SetLocalDescription(ans); err != nil {
		return "", "", err
	}
	select {
	case <-gather:
	case <-time.After(5 * time.Second):
		// Reszta kandydatów dojdzie przez OnCandidate.
	}
	local := s.pc.LocalDescription()
	if local == nil {
		return "", "", errors.New("brak lokalnego SDP")
	}
	fp := Fingerprint(local.SDP)
	if fp == "" {
		return "", "", errors.New("odpowiedź SDP bez odcisku DTLS")
	}
	return local.SDP, fp, nil
}

// AddCandidate dodaje kandydata ICE widza, który dotarł po ofercie.
func (s *Session) AddCandidate(candidate, sdpMid string) error {
	init := webrtc.ICECandidateInit{Candidate: candidate}
	if sdpMid != "" {
		init.SDPMid = &sdpMid
	}
	return s.pc.AddICECandidate(init)
}

func (s *Session) start() {
	s.mu.Lock()
	if s.started || s.ended {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.connectedAt = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	done := make(chan struct{})
	s.engineDone = done
	s.mu.Unlock()
	go func() {
		defer close(done)
		if err := s.runEngine(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("silnik zakończony błędem", "err", err)
		}
	}()
	if s.o.OnState != nil {
		s.o.OnState(StateConnected, s.Stats())
	}
}

// end kończy sesję (raz): najpierw odcina wejście i puszcza klawisze oraz przyciski (to ma być natychmiastowe, zanim
// usługa zabije proces), potem zatrzymuje silnik i zgłasza stan końcowy.
func (s *Session) end(state string) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	cancel, done := s.cancel, s.engineDone
	s.mu.Unlock()
	s.inputOff.Store(true)
	s.o.Engine.SetOnPath(nil)
	if n := s.pressd.ReleaseAll(s.o.Injector); n > 0 {
		s.log.Info("puszczono klawisze i przyciski po zakończeniu sesji", "count", n)
	}
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	if s.o.OnState != nil {
		s.o.OnState(state, s.Stats())
	}
}

// Close kończy sesję (na polecenie usługi).
func (s *Session) Close() {
	s.end(StateDisconnected)
	_ = s.pc.Close()
}

// Stats zwraca podsumowanie sesji.
func (s *Session) Stats() wire.RemoteStats {
	es := s.o.Engine.Stats()
	cfg := s.o.Engine.Config()
	st := wire.RemoteStats{BytesOut: s.bytesOut.Load(), BytesIn: s.bytesIn.Load(), Frames: s.frames.Load(), Encoder: es.Encoder, Width: es.Width, Height: es.Height, Monitor: cfg.Monitor, FPS: cfg.FPS}
	s.mu.Lock()
	if !s.connectedAt.IsZero() {
		st.DurationMs = time.Since(s.connectedAt).Milliseconds()
	}
	s.mu.Unlock()
	return st
}

// WriteFrame (engine.Sink) pakietyzuje klatkę H.264 do RTP i wysyła ścieżką wideo; metadane idą kanałem "meta".
func (s *Session) WriteFrame(data []byte, key bool, rtpTS uint32, capturedMs float64) error {
	payloads := s.pay.Payload(1200, data)
	for i, p := range payloads {
		pkt := &rtp.Packet{
			Header:  rtp.Header{Version: 2, Marker: i == len(payloads)-1, SequenceNumber: s.seq.NextSequenceNumber(), Timestamp: rtpTS},
			Payload: p,
		}
		if err := s.track.WriteRTP(pkt); err != nil {
			return err
		}
		s.bytesOut.Add(int64(len(p) + 12))
	}
	s.frames.Add(1)
	s.mu.Lock()
	dc := s.meta
	s.mu.Unlock()
	if dc != nil {
		s.sendJSON(dc, map[string]any{"t": "f", "ts": rtpTS, "c": capturedMs, "s": proc.WallMs(), "sz": len(data), "k": key})
	}
	return nil
}

// Pointer (engine.Sink) wysyła położenie i kształt kursora kanałem "cursor".
func (s *Session) Pointer(p capture.Pointer) {
	s.mu.Lock()
	if p.Shape == nil {
		p.Shape = s.lastPtr.Shape
	}
	s.lastPtr = p
	s.lastPtr.Moved = true
	s.mu.Unlock()
	s.sendPointer(p, false)
}

func (s *Session) sendPointer(p capture.Pointer, full bool) {
	s.mu.Lock()
	dc := s.cursor
	s.mu.Unlock()
	if dc == nil {
		return
	}
	if p.Shape != nil && (full || !s.shapeSent(p.Shape)) {
		var buf bytes.Buffer
		if err := png.Encode(&buf, p.Shape.Image); err == nil {
			b := p.Shape.Image.Bounds()
			s.sendJSON(dc, map[string]any{"t": "shape", "w": b.Dx(), "h": b.Dy(), "hx": p.Shape.HotX, "hy": p.Shape.HotY, "png": base64.StdEncoding.EncodeToString(buf.Bytes())})
		}
	}
	if p.Moved || full {
		s.sendJSON(dc, map[string]any{"t": "pos", "x": p.X, "y": p.Y, "v": p.Visible})
	}
}

// shapeSent pamięta ostatni wysłany kształt, żeby nie powtarzać PNG przy każdym ruchu.
func (s *Session) shapeSent(sh *capture.PointerShape) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sentShape == sh {
		return true
	}
	s.sentShape = sh
	return false
}

func (s *Session) sendJSON(dc *webrtc.DataChannel, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if err := dc.SendText(string(b)); err == nil {
		s.bytesOut.Add(int64(len(b)))
	}
}

func (s *Session) onInput(raw []byte) {
	if s.inputOff.Load() {
		return // po zakończeniu sesji nic już nie wstrzykujemy, nawet gdy kanał jeszcze dowozi ramki
	}
	s.bytesIn.Add(int64(len(raw)))
	m, ok := ParseInput(raw)
	if !ok {
		return
	}
	switch m.T {
	case "ping":
		s.mu.Lock()
		dc := s.meta
		s.mu.Unlock()
		if dc != nil {
			s.sendJSON(dc, map[string]any{"t": "pong", "tc": m.TC, "tg": proc.WallMs()})
		}
		return
	case "release":
		if n := s.pressd.ReleaseAll(s.o.Injector); n > 0 {
			s.log.Debug("puszczono klawisze na żądanie widza", "count", n)
		}
		return
	case "cfg":
		if m.Mon == nil && m.FPS == nil {
			return
		}
		// Zmiana monitora albo klatek: silnik startuje od nowa na tym samym połączeniu; przy zmianie monitora
		// puszczamy wciśnięte klawisze, żeby nie zostały w poprzednim kontekście.
		if m.Mon != nil {
			s.pressd.ReleaseAll(s.o.Injector)
		}
		s.o.Engine.Reconfigure(func(c *engine.Config) {
			if m.Mon != nil {
				c.Monitor = *m.Mon
			}
			if m.FPS != nil {
				c.FPS = *m.FPS
			}
		})
		if s.o.OnConfig != nil {
			s.o.OnConfig(m.Mon, m.FPS)
		}
		return
	}
	if s.o.Injector == nil {
		s.rejectInput("ctrl", "tylko podgląd: wstrzykiwanie wejścia wyłączone w tej sesji")
		return
	}
	if _, err := Apply(s.o.Injector, s.pressd, m); err != nil {
		s.logInputError(m.T, err)
	}
}
