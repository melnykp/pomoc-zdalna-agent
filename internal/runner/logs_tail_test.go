package runner_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

func TestLogsTailReturnsRedactedTailOverChannel(t *testing.T) {
	e := setup(t, "approved")
	logs := t.TempDir()
	body := strings.Join([]string{
		`{"msg":"start agenta"}`,
		`{"msg":"remote.otp wysłane","otp":"Jednorazowe2026HasloSesji"}`,
		`{"msg":"pomocnik: wejście odrzucone","channel":"ctrl"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "agent.log"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e.opts.LogDir = logs
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	if err := e.srv.Send(deviceID, cmd(t, "logs-1", wire.CmdLogsTail, map[string]any{"lines": 2, "source": "agent"})); err != nil {
		t.Fatal(err)
	}
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("wynik: %+v", res)
	}
	var out wire.LogsTailResult
	if err := json.Unmarshal(res.Result, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sources) != 1 || out.Sources[0].Name != "agent.log" || len(out.Sources[0].Lines) != 2 {
		t.Fatalf("źródła: %+v", out.Sources)
	}
	joined := strings.Join(out.Sources[0].Lines, "\n")
	if strings.Contains(joined, "Jednorazowe2026HasloSesji") || out.Redacted != 1 || !strings.Contains(joined, "wejście odrzucone") {
		t.Fatalf("wynik nie jest przefiltrowany albo nie zawiera ogona:\n%s (zastąpiono %d)", joined, out.Redacted)
	}
}

func TestLogsTailDefaultsAndBadPayload(t *testing.T) {
	e := setup(t, "approved")
	e.opts.LogDir = t.TempDir() // pusty katalog: brak plików to nie błąd polecenia
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	if err := e.srv.Send(deviceID, cmd(t, "logs-2", wire.CmdLogsTail, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil || !res.OK {
		t.Fatalf("wynik: %+v err=%v", res, err)
	}
	var out wire.LogsTailResult
	if err := json.Unmarshal(res.Result, &out); err != nil || len(out.Sources) != 2 || !out.Sources[0].Missing || !out.Sources[1].Missing {
		t.Fatalf("puste katalogi powinny dać dwa źródła z Missing: %+v err=%v", out, err)
	}

	if err := e.srv.Send(deviceID, cmd(t, "logs-3", wire.CmdLogsTail, map[string]any{"lines": "dużo"})); err != nil {
		t.Fatal(err)
	}
	var bad wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&bad); err != nil {
		t.Fatal(err)
	}
	if bad.OK || !strings.Contains(bad.Error, "logs.tail") {
		t.Fatalf("zły ładunek powinien zwrócić błąd: %+v", bad)
	}
}
