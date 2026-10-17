package installer_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/fakeserver"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/installer"
)

const token = "k3Jx9QpL0vT2mN8sB4wZ7cH1yD6fG5aR-eU_oI3nM9q"

func newServer(t *testing.T, status string) (*fakeserver.Server, *int) {
	t.Helper()
	srv := fakeserver.New(t)
	calls := 0
	srv.EnrollHandler = func(body map[string]any) (int, any) {
		calls++
		if body["invitation_token"] != token {
			return http.StatusUnauthorized, map[string]string{"code": "enrollment_invalid", "message": "x"}
		}
		return http.StatusCreated, map[string]any{
			"device_id":   "7a0d1c2e-0000-4000-8000-000000000001",
			"status":      status,
			"ws_url":      srv.WSURL(),
			"short_code":  "7A0D1C2E",
			"server_keys": []map[string]string{{"key_id": "test", "public_key": "AAAA"}},
		}
	}
	return srv, &calls
}

func TestEnrollWritesIdentityAndConfig(t *testing.T) {
	srv, _ := newServer(t, "pending")
	dir := filepath.Join(t.TempDir(), "RMM")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := installer.Enroll(ctx, installer.Params{ServerURL: srv.URL(), Token: token, DataDir: dir, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "pending" || res.ShortCode != "7A0D1C2E" || res.Repeated {
		t.Fatalf("wynik: %+v", res)
	}

	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DeviceID != res.DeviceID || cfg.ServerURL != srv.URL() || len(cfg.ServerKeys) != 1 {
		t.Fatalf("konfiguracja: %+v", cfg)
	}
	id, created, err := identity.LoadOrCreate(filepath.Join(dir, "identity.bin"))
	if err != nil || created || len(id.Private) == 0 {
		t.Fatalf("tożsamość powinna istnieć po rejestracji: created=%v err=%v", created, err)
	}
}

func TestEnrollSendsTheDevicePublicKey(t *testing.T) {
	srv := fakeserver.New(t)
	var sent map[string]any
	srv.EnrollHandler = func(body map[string]any) (int, any) {
		sent = body
		return http.StatusCreated, map[string]any{"device_id": "7a0d1c2e-0000-4000-8000-000000000001", "status": "approved"}
	}
	dir := t.TempDir()
	res, err := installer.Enroll(context.Background(), installer.Params{ServerURL: srv.URL(), Token: token, DataDir: dir, Version: "2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	id, _, _ := identity.LoadOrCreate(filepath.Join(dir, "identity.bin"))
	if sent["public_key"] != id.PublicBase64() || sent["agent_version"] != "2.0.0" || sent["arch"] == "" || sent["hostname"] == "" {
		t.Fatalf("serwer dostał: %v", sent)
	}
	if res.ShortCode != "7A0D1C2E" {
		t.Fatalf("skrót wyprowadzony z device_id: %q", res.ShortCode)
	}
}

func TestEnrollIsIdempotentForTheSameServer(t *testing.T) {
	srv, calls := newServer(t, "approved")
	dir := t.TempDir()
	p := installer.Params{ServerURL: srv.URL(), Token: token, DataDir: dir}

	if _, err := installer.Enroll(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	res, err := installer.Enroll(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Repeated || *calls != 1 {
		t.Fatalf("drugie uruchomienie nie powinno zużywać zaproszenia: repeated=%v wywołań=%d", res.Repeated, *calls)
	}
}

func TestEnrollWithBadTokenLeavesNoConfig(t *testing.T) {
	srv, _ := newServer(t, "pending")
	dir := t.TempDir()
	_, err := installer.Enroll(context.Background(), installer.Params{ServerURL: srv.URL(), Token: "zly-token", DataDir: dir})
	if err == nil {
		t.Fatal("zły token powinien dać błąd")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.json")); statErr == nil {
		t.Fatal("nieudana rejestracja nie może zostawić konfiguracji")
	}
}
