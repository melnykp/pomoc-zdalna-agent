// Package session realizuje stronę agenta handshake z docs/ARCHITECTURE.md:
// hello od serwera, auth podpisany kluczem urządzenia, auth.ok z podpisem serwera
// sprawdzanym zaufanym kluczem. Dopiero po tym kanał jest uwierzytelniony w obie strony.
package session

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/melnykp/pomoc-zdalna-agent/internal/protocol"
	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Params to dane potrzebne do handshake.
type Params struct {
	DeviceID string
	Private  ed25519.PrivateKey
	// ServerKeys to zaufane klucze publiczne serwera; auth.ok musi być podpisany którymś z nich.
	ServerKeys []ed25519.PublicKey
	Versions   wire.Versions
	Caps       []string
}

// Info opisuje nawiązaną sesję.
type Info struct {
	SessionID  string
	HeartbeatS int
	InventoryH int
	ServerTime int64
}

// RejectedError oznacza, że serwer odmówił uwierzytelnienia (auth.fail).
type RejectedError struct {
	Reason string
	RetryS int
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("serwer odmówił uwierzytelnienia: %s", e.Reason)
}

// ErrUntrustedServer oznacza podpis serwera, którego nie da się zweryfikować zaufanym kluczem.
var ErrUntrustedServer = errors.New("session: podpis serwera nie zgadza się z zaufanym kluczem")

// Handshake wykonuje wzajemne uwierzytelnienie na świeżo otwartym kanale.
func Handshake(ctx context.Context, conn transport.Conn, p Params) (Info, error) {
	if len(p.ServerKeys) == 0 {
		return Info{}, errors.New("session: brak zaufanych kluczy serwera")
	}

	helloEnv, err := conn.Recv(ctx)
	if err != nil {
		return Info{}, fmt.Errorf("session: oczekiwanie na hello: %w", err)
	}
	if helloEnv.T != wire.TypeHello {
		return Info{}, fmt.Errorf("session: oczekiwano hello, przyszło %q", helloEnv.T)
	}
	var hello wire.Hello
	if err := helloEnv.Decode(&hello); err != nil {
		return Info{}, fmt.Errorf("session: zły hello: %w", err)
	}
	if !slices.Contains(hello.ProtocolVersions, wire.ProtocolVersion) {
		return Info{}, fmt.Errorf("session: serwer nie obsługuje protokołu v%d", wire.ProtocolVersion)
	}

	agentNonce, err := protocol.NewNonce()
	if err != nil {
		return Info{}, err
	}
	sig := protocol.SignAgentAuth(p.Private, hello.ServerNonce, agentNonce, p.DeviceID)
	auth, err := wire.NewEnvelope(wire.TypeAuth, wire.Auth{
		DeviceID:            p.DeviceID,
		AgentNonce:          agentNonce,
		AgentVersion:        p.Versions.Agent,
		WatchdogVersion:     p.Versions.Watchdog,
		RemoteModuleVersion: p.Versions.Remote,
		HelperVersion:       p.Versions.Helper,
		RemoteEngine:        p.Versions.RemoteEngine,
		HelperLevel:         p.Versions.HelperLevel,
		HelperLevelCfg:      p.Versions.HelperLevelCfg,
		HelperToken:         p.Versions.HelperToken,
		HelperFallback:      p.Versions.HelperFallback,
		HelperLevelSession:  p.Versions.HelperLevelSession,
		UAC:                 p.Versions.UAC,
		Caps:                p.Caps,
		Sig:                 protocol.EncodeSig(sig),
	})
	if err != nil {
		return Info{}, err
	}
	if err := conn.Send(ctx, auth); err != nil {
		return Info{}, fmt.Errorf("session: wysyłka auth: %w", err)
	}

	resp, err := conn.Recv(ctx)
	if err != nil {
		return Info{}, fmt.Errorf("session: oczekiwanie na auth.ok: %w", err)
	}
	switch resp.T {
	case wire.TypeAuthOK:
		var ok wire.AuthOK
		if err := resp.Decode(&ok); err != nil {
			return Info{}, fmt.Errorf("session: zły auth.ok: %w", err)
		}
		serverSig, err := protocol.DecodeSig(ok.Sig)
		if err != nil {
			return Info{}, ErrUntrustedServer
		}
		trusted := false
		for _, k := range p.ServerKeys {
			if protocol.VerifyServerAuth(k, hello.ServerNonce, agentNonce, p.DeviceID, serverSig) {
				trusted = true
				break
			}
		}
		if !trusted {
			return Info{}, ErrUntrustedServer
		}
		return Info{SessionID: ok.SessionID, HeartbeatS: ok.HeartbeatS, InventoryH: ok.InventoryH, ServerTime: ok.Time}, nil
	case wire.TypeAuthFail:
		var f wire.AuthFail
		if err := resp.Decode(&f); err != nil {
			return Info{}, fmt.Errorf("session: zły auth.fail: %w", err)
		}
		return Info{}, &RejectedError{Reason: f.Reason, RetryS: f.RetryS}
	case wire.TypeError:
		var e wire.ErrorMsg
		_ = resp.Decode(&e)
		return Info{}, fmt.Errorf("session: serwer zgłosił błąd %s: %s", e.Code, e.Message)
	default:
		return Info{}, fmt.Errorf("session: nieoczekiwana wiadomość %q po auth", resp.T)
	}
}
