package ipc

import (
	"bufio"
	"bytes"
	"testing"
)

func TestLineRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Kind: KindApply, Component: "agent", Path: `C:\ProgramData\RMM\staging\agent.exe`, Version: "1.3.0", SHA256: "abc"}
	if err := WriteLine(&buf, req); err != nil {
		t.Fatal(err)
	}
	if err := WriteLine(&buf, Response{OK: true, Version: "1.3.0"}); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(&buf)
	var gotReq Request
	if err := ReadLine(r, &gotReq); err != nil {
		t.Fatal(err)
	}
	if gotReq != req {
		t.Fatalf("żądanie po odczycie różni się: %+v", gotReq)
	}
	var gotRes Response
	if err := ReadLine(r, &gotRes); err != nil {
		t.Fatal(err)
	}
	if !gotRes.OK || gotRes.Version != "1.3.0" {
		t.Fatalf("odpowiedź po odczycie różni się: %+v", gotRes)
	}
}
