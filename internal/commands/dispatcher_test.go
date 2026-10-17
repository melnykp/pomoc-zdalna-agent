package commands

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

func TestExecuteSuccessAndDuplicate(t *testing.T) {
	d := New(time.Second)
	calls := 0
	d.Register("echo", func(_ context.Context, cmd wire.Cmd) (json.RawMessage, error) {
		calls++
		return cmd.Payload, nil
	})
	cmd := wire.Cmd{CommandID: "c1", Type: "echo", Payload: json.RawMessage(`{"x":1}`)}

	res, dup := d.Execute(context.Background(), cmd, time.Now())
	if dup || !res.OK || string(res.Result) != `{"x":1}` || res.CommandID != "c1" {
		t.Fatalf("zły wynik: %+v dup=%v", res, dup)
	}
	if _, dup := d.Execute(context.Background(), cmd, time.Now()); !dup {
		t.Fatal("powtórzone polecenie powinno być rozpoznane")
	}
	if calls != 1 {
		t.Fatalf("handler wywołany %d razy, oczekiwano 1", calls)
	}
}

func TestExecuteErrors(t *testing.T) {
	d := New(50 * time.Millisecond)
	d.Register("fail", func(context.Context, wire.Cmd) (json.RawMessage, error) {
		return nil, errors.New("coś poszło nie tak")
	})
	d.Register("slow", func(ctx context.Context, _ wire.Cmd) (json.RawMessage, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	if res, _ := d.Execute(context.Background(), wire.Cmd{CommandID: "u", Type: "nope"}, time.Now()); res.OK || res.Error != ErrUnknownCommand {
		t.Fatalf("nieznane polecenie: %+v", res)
	}
	if res, _ := d.Execute(context.Background(), wire.Cmd{CommandID: "f", Type: "fail"}, time.Now()); res.OK || res.Error != "coś poszło nie tak" {
		t.Fatalf("błąd handlera: %+v", res)
	}
	if res, _ := d.Execute(context.Background(), wire.Cmd{CommandID: "s", Type: "slow"}, time.Now()); res.OK || res.Error != ErrTimeout {
		t.Fatalf("przekroczenie czasu: %+v", res)
	}
	past := time.Now().Add(-time.Minute).UnixMilli()
	if res, _ := d.Execute(context.Background(), wire.Cmd{CommandID: "e", Type: "fail", ExpiresAt: past}, time.Now()); res.OK || res.Error != ErrExpired {
		t.Fatalf("wygasłe polecenie: %+v", res)
	}
}

func TestRingForgetsOldest(t *testing.T) {
	r := newRing(3)
	for _, id := range []string{"a", "b", "c"} {
		r.add(id)
	}
	r.add("d")
	if r.has("a") || !r.has("b") || !r.has("d") {
		t.Fatal("pierścień nie wypiera najstarszego identyfikatora")
	}
	if len(r.idx) != 3 {
		t.Fatalf("indeks ma %d wpisów, oczekiwano 3", len(r.idx))
	}
}
