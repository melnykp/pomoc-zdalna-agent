package enroll_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/enroll"
	"github.com/melnykp/pomoc-zdalna-agent/internal/fakeserver"
)

func TestEnrollSuccess(t *testing.T) {
	srv := fakeserver.New(t)
	var got map[string]any
	srv.EnrollHandler = func(body map[string]any) (int, any) {
		got = body
		return http.StatusCreated, map[string]any{
			"device_id":   "7a0d1c2e-0000-4000-8000-000000000001",
			"status":      "pending",
			"ws_url":      srv.WSURL(),
			"short_code":  "7A0D1C2E",
			"server_keys": []map[string]string{{"key_id": "dev", "public_key": "AAAA"}},
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := enroll.Do(ctx, nil, srv.URL()+"/", enroll.Request{InvitationToken: "t", PublicKey: "k", Hostname: "PC", OSFamily: "windows", Arch: "amd64", AgentVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.DeviceID == "" || res.Status != "pending" || res.ShortCode != "7A0D1C2E" || len(res.ServerKeys) != 1 {
		t.Fatalf("odpowiedź: %+v", res)
	}
	if got["invitation_token"] != "t" || got["os_family"] != "windows" || got["hostname"] != "PC" {
		t.Fatalf("serwer dostał: %v", got)
	}
	if _, has := got["hw_id"]; has {
		t.Fatalf("puste pola opcjonalne nie powinny być wysyłane: %v", got)
	}
}

func TestEnrollRejected(t *testing.T) {
	srv := fakeserver.New(t) // domyślnie 401 enrollment_invalid
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := enroll.Do(ctx, nil, srv.URL(), enroll.Request{InvitationToken: "zly"})
	var e *enroll.Error
	if !errors.As(err, &e) || e.Status != 401 || e.Code != enroll.CodeInvalidInvitation {
		t.Fatalf("oczekiwano błędu 401 enrollment_invalid, jest: %v", err)
	}
	if msg := enroll.Explain(err); msg == "" || msg == enroll.Explain(errors.New("siec")) {
		t.Fatalf("komunikat dla człowieka powinien odróżniać wygasłe zaproszenie od braku sieci: %q", msg)
	}
}

func TestEnrollConflictAndNetwork(t *testing.T) {
	srv := fakeserver.New(t)
	srv.EnrollHandler = func(map[string]any) (int, any) {
		return http.StatusConflict, map[string]any{"code": enroll.CodeAlreadyEnrolled, "message": "x"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := enroll.Do(ctx, nil, srv.URL(), enroll.Request{})
	if enroll.Explain(err) != "Ten komputer jest już zarejestrowany." {
		t.Fatalf("komunikat: %q", enroll.Explain(err))
	}

	if _, err := enroll.Do(ctx, nil, "http://127.0.0.1:1", enroll.Request{}); err == nil {
		t.Fatal("brak serwera powinien dać błąd")
	}
}

func TestEnrollRejectsResponseWithoutDeviceID(t *testing.T) {
	srv := fakeserver.New(t)
	srv.EnrollHandler = func(map[string]any) (int, any) { return http.StatusCreated, map[string]any{"status": "pending"} }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := enroll.Do(ctx, nil, srv.URL(), enroll.Request{}); err == nil {
		t.Fatal("odpowiedź bez device_id nie może być przyjęta")
	}
}
