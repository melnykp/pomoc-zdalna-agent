package wire

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	env, err := NewEnvelope(TypeHeartbeat, Heartbeat{CPUPct: 12.5, UptimeS: 42})
	if err != nil {
		t.Fatal(err)
	}
	if env.V != ProtocolVersion || env.T != TypeHeartbeat || env.ID == "" || env.TS == 0 {
		t.Fatalf("zła koperta: %+v", env)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	var hb Heartbeat
	if err := back.Decode(&hb); err != nil {
		t.Fatal(err)
	}
	if hb.CPUPct != 12.5 || hb.UptimeS != 42 {
		t.Fatalf("zła treść: %+v", hb)
	}
}

func TestReplyReferencesRequest(t *testing.T) {
	req, _ := NewEnvelope(TypeCmd, Cmd{CommandID: "c1", Type: CmdInventoryRefresh})
	rep, err := Reply(req, TypeCmdAck, CmdAck{CommandID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Re == nil || *rep.Re != req.ID {
		t.Fatal("odpowiedź nie wskazuje wiadomości źródłowej")
	}
	if rep.ID == req.ID {
		t.Fatal("odpowiedź musi mieć własny identyfikator")
	}
}

func TestRemoteSignalRoundTripKeepsFingerprintAndICE(t *testing.T) {
	in := RemoteSignal{SessionID: "s1", Kind: SignalOffer, SDP: "v=0\r\n", Fingerprint: "AB:CD",
		ICEServers: []ICEServer{{URLs: []string{"stun:stun.example.pl:3478"}}, {URLs: []string{"turn:turn.example.pl:3478"}, Username: "u", Credential: "c"}}}
	env, err := NewEnvelope(TypeRemoteSignal, in)
	if err != nil {
		t.Fatal(err)
	}
	var out RemoteSignal
	if err := env.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.SessionID != in.SessionID || out.Kind != SignalOffer || out.SDP != in.SDP || out.Fingerprint != in.Fingerprint || len(out.ICEServers) != 2 || out.ICEServers[1].Credential != "c" {
		t.Fatalf("zła treść: %+v", out)
	}
	// Pola puste nie trafiają do JSON (odpowiedź nie powtarza listy serwerów ICE ani błędu).
	raw, _ := json.Marshal(RemoteSignal{SessionID: "s1", Kind: SignalAnswer, SDP: "x", Fingerprint: "y"})
	if s := string(raw); s != `{"session_id":"s1","kind":"answer","sdp":"x","fingerprint":"y"}` {
		t.Fatalf("niespodziewany JSON: %s", s)
	}
}

func TestRemoteStateWithoutStatsOmitsField(t *testing.T) {
	raw, _ := json.Marshal(RemoteState{SessionID: "s", State: "connected", PeerID: "", At: 1})
	if s := string(raw); s != `{"session_id":"s","state":"connected","peer_id":"","at":1}` {
		t.Fatalf("niespodziewany JSON: %s", s)
	}
	raw, _ = json.Marshal(RemoteState{SessionID: "s", State: "disconnected", At: 1, Stats: &RemoteStats{DurationMs: 5000, BytesOut: 12, Frames: 3, Monitor: 1}})
	var back RemoteState
	if err := json.Unmarshal(raw, &back); err != nil || back.Stats == nil || back.Stats.BytesOut != 12 || back.Stats.Monitor != 1 {
		t.Fatalf("statystyki nie przeszły: %s (%v)", raw, err)
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 10000; i++ {
		id := NewID()
		if len(id) != 32 {
			t.Fatalf("zła długość id: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("powtórzony identyfikator: %q", id)
		}
		seen[id] = struct{}{}
	}
}
