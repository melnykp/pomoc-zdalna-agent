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
