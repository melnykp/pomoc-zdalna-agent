package ipc

import "github.com/melnykp/pomoc-zdalna-agent/pkg/wire"

// Komunikaty między usługą agenta (SYSTEM) a pomocnikiem pulpitu uruchamianym w sesji użytkownika
// (docs/adr/0009-wlasny-silnik-pulpitu.md, korekty po prototypie, pkt 1). Rozmowa idzie przez standardowe wejście
// i wyjście pomocnika (potoki odziedziczone przy CreateProcessAsUser), w tym samym kodowaniu linii JSON co WriteLine
// i ReadLine. Pomocnik niczego nie nasłuchuje w sieci poza samym WebRTC i nie zna serwera: całą sygnalizację
// przekazuje usługa swoim uwierzytelnionym kanałem.

// DesktopKind to rodzaj komunikatu pomocnika pulpitu.
type DesktopKind string

// Komunikaty usługa → pomocnik.
const (
	// DesktopStart zaczyna sesję: oferta SDP widza (po sprawdzeniu przez serwer), lista serwerów ICE, czy wolno sterować.
	DesktopStart DesktopKind = "start"
	// DesktopSignal przekazuje kandydata ICE od widza.
	DesktopSignal DesktopKind = "signal"
	// DesktopStop kończy sesję: pomocnik puszcza klawisze i przyciski, zamyka połączenie i kończy proces.
	DesktopStop DesktopKind = "stop"
)

// Komunikaty pomocnik → usługa.
const (
	// DesktopReady: pomocnik wstał, podaje monitory; bez DesktopStart w ciągu kilkudziesięciu sekund kończy się sam.
	DesktopReady DesktopKind = "ready"
	// DesktopAnswer: odpowiedź SDP z odciskiem DTLS pomocnika.
	DesktopAnswer DesktopKind = "answer"
	// DesktopCandidate: kandydat ICE pomocnika do przekazania widzowi.
	DesktopCandidate DesktopKind = "candidate"
	// DesktopState: zmiana stanu połączenia (StateConnected, StateDisconnected, StateFailed) ze statystykami przy końcu.
	DesktopState DesktopKind = "state"
	// DesktopLog: linia dziennika pomocnika do zapisania w logu usługi.
	DesktopLog DesktopKind = "log"
)

// Stany połączenia zgłaszane przez pomocnika.
const (
	StateConnected    = "connected"
	StateDisconnected = "disconnected"
	StateFailed       = "failed"
)

// DesktopDisplay opisuje monitor widziany przez pomocnika (do wyboru monitora w panelu).
type DesktopDisplay struct {
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Left    int    `json:"left"`
	Top     int    `json:"top"`
	Primary bool   `json:"primary"`
}

// DesktopMsg to jeden komunikat w dowolnym kierunku; pola zależą od Kind.
type DesktopMsg struct {
	Kind      DesktopKind `json:"kind"`
	SessionID string      `json:"session_id,omitempty"`

	// start, answer
	SDP         string           `json:"sdp,omitempty"`
	Fingerprint string           `json:"fingerprint,omitempty"`
	ICEServers  []wire.ICEServer `json:"ice_servers,omitempty"`
	Control     bool             `json:"control,omitempty"`
	Monitor     int              `json:"monitor,omitempty"`
	FPS         int              `json:"fps,omitempty"`

	// signal, candidate
	Candidate string `json:"candidate,omitempty"`
	SDPMid    string `json:"sdp_mid,omitempty"`

	// state
	State string            `json:"state,omitempty"`
	Stats *wire.RemoteStats `json:"stats,omitempty"`
	Error string            `json:"error,omitempty"`

	// ready
	Displays []DesktopDisplay `json:"displays,omitempty"`
	Version  string           `json:"version,omitempty"`

	// log
	Level string `json:"level,omitempty"`
	Text  string `json:"text,omitempty"`
}
