package peer

import (
	"encoding/json"
	"testing"
)

func TestInputStatsSnapshotRoundTripsAsJSON(t *testing.T) {
	var s InputStats
	s.RxCtrl.Add(7)
	s.RxMouse.Add(120)
	s.Injected.Add(118)
	s.NoteError("SendInput(mysz): odmowa dostępu")
	s.NoteError("SendInput(klawisz): odmowa dostępu")
	s.NoteReject("certyfikat DTLS niedostępny")
	s.NoteMismatch("cel (10,10), kursor (500,300)")
	m := s.Snapshot()
	m.Channels = map[string]bool{"ctrl": true, "mouse": true, "cursor": false, "meta": true}
	m.DTLS = DTLSLabel(1)
	m.Control = true
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back InputStatsMsg
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.T != "input" || back.Rx.Ctrl != 7 || back.Rx.Mouse != 120 || back.Injected != 118 || back.Errors != 2 || back.Rejected != 1 || back.Mismatch != 1 {
		t.Fatalf("liczniki: %+v", back)
	}
	if back.LastError != "SendInput(klawisz): odmowa dostępu" || back.LastReject == "" || back.LastMismatch == "" {
		t.Fatalf("ostatnie błędy: %+v", back)
	}
	if back.DTLS != "zgodny" || !back.Control || back.Channels["cursor"] || !back.Channels["meta"] {
		t.Fatalf("stan: %+v", back)
	}
}

func TestDTLSLabel(t *testing.T) {
	if DTLSLabel(0) != "oczekuje" || DTLSLabel(1) != "zgodny" || DTLSLabel(-1) != "niezgodny" {
		t.Fatal("etykiety weryfikacji")
	}
}
