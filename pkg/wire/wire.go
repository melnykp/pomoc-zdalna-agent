// Package wire definiuje protokół agent↔serwer w wersji 1 (docs/ARCHITECTURE.md).
//
// Ten pakiet jest jedynym źródłem prawdy dla protokołu. Typy TypeScript po stronie
// serwera (server/src/modules/agent-gateway/wire.ts) odzwierciedlają te struktury
// i docelowo będą z nich generowane.
package wire

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// ProtocolVersion to wersja koperty i zestawu wiadomości.
const ProtocolVersion = 1

// Domeny podpisów w handshake. Osobne stałe dla agenta i serwera uniemożliwiają
// odbicie podpisu jednej strony jako podpisu drugiej.
const (
	AuthDomainAgent  = "rmm-auth-v1"
	AuthDomainServer = "rmm-srv-v1"
)

// Typy wiadomości (pole "t" koperty).
const (
	TypeHello            = "hello"
	TypeAuth             = "auth"
	TypeAuthOK           = "auth.ok"
	TypeAuthFail         = "auth.fail"
	TypeAuthRetry        = "auth.retry"
	TypeHeartbeat        = "hb"
	TypeInventoryFull    = "inventory.full"
	TypeCmd              = "cmd"
	TypeCmdAck           = "cmd.ack"
	TypeCmdResult        = "cmd.result"
	TypeCmdResultAck     = "cmd.result.ack"
	TypeRemoteOTP        = "remote.otp"
	TypeRemoteState      = "remote.state"
	TypeUpdateStatus     = "update.status"
	TypeReleaseAvailable = "release.available"
	TypeReleaseRequest   = "release.request"
	TypeEvent            = "event"
	TypeError            = "error"
)

// Typy poleceń fazy 1 (pole Cmd.Type).
const (
	CmdInventoryRefresh = "inventory.refresh"
	CmdRemoteOpen       = "remote.open"
	CmdRemoteClose      = "remote.close"
	CmdUpdateCheck      = "update.check"
	CmdUpdateApply      = "update.apply"
	CmdAgentRestart     = "agent.restart"
	CmdConfigSet        = "config.set"
	CmdDeviceRetire     = "device.retire"
)

// Powody odmowy w AuthFail.
const (
	AuthFailPending       = "pending"
	AuthFailBlocked       = "blocked"
	AuthFailRetired       = "retired"
	AuthFailBadSignature  = "bad_signature"
	AuthFailUnknownDevice = "unknown_device"
)

// Stany aktualizacji (UpdateStatus.State).
const (
	UpdateDownloading = "downloading"
	UpdateVerified    = "verified"
	UpdateApplying    = "applying"
	UpdateSuccess     = "success"
	UpdateRolledBack  = "rolled_back"
	UpdateFailed      = "failed"
)

// Rodzaje zdarzeń lokalnych (Event.Kind).
const (
	EventTamper         = "tamper"
	EventServiceRestart = "service_restart"
	EventCrashLoop      = "crash_loop"
	EventClockSkew      = "clock_skew"
)

// Envelope to koperta każdej wiadomości.
type Envelope struct {
	V  int             `json:"v"`
	T  string          `json:"t"`
	ID string          `json:"id"`
	TS int64           `json:"ts"`
	Re *string         `json:"re"`
	D  json.RawMessage `json:"d"`
}

// NewEnvelope opakowuje dane d w kopertę typu t.
func NewEnvelope(t string, d any) (Envelope, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{V: ProtocolVersion, T: t, ID: NewID(), TS: time.Now().UnixMilli(), D: raw}, nil
}

// Reply tworzy odpowiedź na kopertę req (pole "re" wskazuje jej id).
func Reply(req Envelope, t string, d any) (Envelope, error) {
	env, err := NewEnvelope(t, d)
	if err != nil {
		return Envelope{}, err
	}
	id := req.ID
	env.Re = &id
	return env, nil
}

// Decode dekoduje pole D koperty do v.
func (e Envelope) Decode(v any) error {
	return json.Unmarshal(e.D, v)
}

// NewID zwraca losowy identyfikator wiadomości (128 bitów, hex).
// Docelowo ULID; wymagana jest tylko unikalność, nie porządek.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("wire: brak źródła losowości: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ---- serwer → agent ----

// Hello otwiera handshake po stronie serwera.
type Hello struct {
	ServerNonce      string `json:"server_nonce"`
	ServerKeyID      string `json:"server_key_id"`
	ProtocolVersions []int  `json:"protocol_versions"`
	Time             int64  `json:"time"`
}

// AuthOK potwierdza uwierzytelnienie; Sig to base64 podpisu Ed25519 serwera
// nad wiadomością w domenie AuthDomainServer.
type AuthOK struct {
	SessionID  string `json:"session_id"`
	HeartbeatS int    `json:"heartbeat_s"`
	InventoryH int    `json:"inventory_h"`
	Time       int64  `json:"time"`
	Sig        string `json:"sig"`
}

// AuthFail odrzuca uwierzytelnienie z powodem z AuthFail*.
type AuthFail struct {
	Reason string `json:"reason"`
	// RetryS mówi, za ile sekund ponowić próbę (urządzenie czeka na zatwierdzenie).
	RetryS int `json:"retry_s,omitempty"`
}

// Cmd to polecenie do wykonania przez agenta.
type Cmd struct {
	CommandID string          `json:"command_id"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt int64           `json:"expires_at"`
}

// CmdResultAck potwierdza odbiór wyniku; agent usuwa go z trwałej kolejki.
type CmdResultAck struct {
	CommandID string `json:"command_id"`
}

// ReleaseAvailable to oferta wydania przypiętego do pierścienia urządzenia. Manifest i podpis przychodzą
// w całości, dokładnie tak, jak je podpisano, więc agent weryfikuje je sam i nie ufa kanałowi.
type ReleaseAvailable struct {
	ReleaseID string `json:"release_id"`
	Component string `json:"component"`
	Ring      string `json:"ring"`
	Version   string `json:"version"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

// ReleaseRequest prosi serwer o ofertę wydania dla pierścienia urządzenia.
type ReleaseRequest struct {
	Component string `json:"component"`
}

// Ładunki poleceń.

// RemoteOpenPayload to ładunek CmdRemoteOpen.
type RemoteOpenPayload struct {
	SessionID          string `json:"session_id"`
	TechnicianRemoteID string `json:"technician_remote_id"`
	TTLS               int    `json:"ttl_s"`
}

// RemoteClosePayload to ładunek CmdRemoteClose.
type RemoteClosePayload struct {
	SessionID string `json:"session_id"`
}

// UpdateApplyPayload to ładunek CmdUpdateApply.
type UpdateApplyPayload struct {
	ReleaseID string `json:"release_id"`
}

// ConfigSetPayload to ładunek CmdConfigSet; pola nil pozostają bez zmian.
type ConfigSetPayload struct {
	HeartbeatS *int     `json:"heartbeat_s,omitempty"`
	InventoryH *int     `json:"inventory_h,omitempty"`
	Whitelist  []string `json:"whitelist,omitempty"`
}

// ---- agent → serwer ----

// Versions to wersje komponentów na końcówce.
type Versions struct {
	Agent    string `json:"agent"`
	Watchdog string `json:"watchdog"`
	Remote   string `json:"remote"`
}

// Auth to odpowiedź agenta na Hello; Sig to base64 podpisu Ed25519 urządzenia
// nad wiadomością w domenie AuthDomainAgent.
type Auth struct {
	DeviceID            string   `json:"device_id"`
	AgentNonce          string   `json:"agent_nonce"`
	AgentVersion        string   `json:"agent_version"`
	WatchdogVersion     string   `json:"watchdog_version"`
	RemoteModuleVersion string   `json:"remote_module_version"`
	Caps                []string `json:"caps"`
	Sig                 string   `json:"sig"`
}

// Heartbeat to okresowy raport stanu.
type Heartbeat struct {
	CPUPct     float64  `json:"cpu_pct"`
	MemUsedMB  int64    `json:"mem_used_mb"`
	MemTotalMB int64    `json:"mem_total_mb"`
	UptimeS    int64    `json:"uptime_s"`
	LoggedUser string   `json:"logged_user"`
	IPLocal    []string `json:"ip_local"`
	Versions   Versions `json:"versions"`
}

// CmdAck potwierdza odbiór polecenia (przed wykonaniem).
type CmdAck struct {
	CommandID string `json:"command_id"`
}

// CmdResult to wynik wykonania polecenia.
type CmdResult struct {
	CommandID  string          `json:"command_id"`
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	DurationMs int64           `json:"duration_ms"`
}

// RemoteOTP przekazuje hasło jednorazowe sesji pulpitu.
type RemoteOTP struct {
	SessionID string `json:"session_id"`
	RemoteID  string `json:"remote_id"`
	OTP       string `json:"otp"`
	ExpiresAt int64  `json:"expires_at"`
}

// RemoteState zgłasza zmianę stanu sesji pulpitu.
type RemoteState struct {
	SessionID string `json:"session_id"`
	State     string `json:"state"`
	PeerID    string `json:"peer_id"`
	At        int64  `json:"at"`
}

// UpdateStatus raportuje etap aktualizacji.
type UpdateStatus struct {
	ReleaseID   string `json:"release_id"`
	State       string `json:"state"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Error       string `json:"error,omitempty"`
}

// Event to zdarzenie lokalne na końcówce.
type Event struct {
	Kind    string          `json:"kind"`
	Details json.RawMessage `json:"details,omitempty"`
}

// ErrorMsg to odpowiedź na nieprawidłową wiadomość.
type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
