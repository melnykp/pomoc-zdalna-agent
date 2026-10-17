package config

import (
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := Default()
	ok.ServerURL = "https://agent.example.pl"
	if err := ok.Validate(); err != nil {
		t.Fatalf("poprawna konfiguracja odrzucona: %v", err)
	}

	dev := Default()
	dev.ServerURL = "http://localhost:3200"
	if err := dev.Validate(); err != nil {
		t.Fatalf("localhost po http powinien być dozwolony w rozwoju: %v", err)
	}

	cases := map[string]func(*Config){
		"brak server_url":   func(c *Config) { c.ServerURL = "" },
		"http do internetu": func(c *Config) { c.ServerURL = "http://agent.example.pl" },
		"heartbeat za mały": func(c *Config) { c.HeartbeatSeconds = 1 },
		"inventory za duży": func(c *Config) { c.InventoryHours = 1000 },
		"zły pierścień":     func(c *Config) { c.Ring = "beta" },
		"zły poziom logów":  func(c *Config) { c.LogLevel = "verbose" },
	}
	for name, mutate := range cases {
		c := Default()
		c.ServerURL = "https://agent.example.pl"
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: konfiguracja powinna być odrzucona", name)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	in := Default()
	in.ServerURL = "https://agent.example.pl"
	in.DeviceID = "dev-1"
	in.Ring = RingCanary
	in.Whitelist = []string{"123456789"}

	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.ServerURL != in.ServerURL || out.DeviceID != in.DeviceID || out.Ring != in.Ring ||
		len(out.Whitelist) != 1 || out.Whitelist[0] != "123456789" {
		t.Fatalf("konfiguracja po odczycie różni się: %+v", out)
	}
}

func TestDataDirOverride(t *testing.T) {
	t.Setenv("RMM_DATA_DIR", t.TempDir())
	if DataDir() == "" || filepath.Base(Path()) != "config.json" {
		t.Fatal("RMM_DATA_DIR nie jest honorowane")
	}
}

func TestChannelURL(t *testing.T) {
	cases := map[string]string{
		"https://agent.example.pl":      "wss://agent.example.pl/v1/agent",
		"https://agent.example.pl/":     "wss://agent.example.pl/v1/agent",
		"https://agent.example.pl/rmm/": "wss://agent.example.pl/rmm/v1/agent",
		"http://127.0.0.1:3200":         "ws://127.0.0.1:3200/v1/agent",
		"https://agent.example.pl/?x=1": "wss://agent.example.pl/v1/agent",
	}
	for in, want := range cases {
		got, err := Config{ServerURL: in}.ChannelURL()
		if err != nil || got != want {
			t.Errorf("%s: %q err=%v, oczekiwano %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x.example", "nie url", "https://"} {
		if got, err := (Config{ServerURL: bad}).ChannelURL(); err == nil {
			t.Errorf("%q: powinien być błąd, jest %q", bad, got)
		}
	}
}

func TestServerKeysSurviveSaveAndLoad(t *testing.T) {
	cfg := Default()
	cfg.ServerURL = "https://agent.example.pl"
	cfg.DeviceID = "7a0d1c2e-0000-4000-8000-000000000001"
	cfg.ServerKeys = []ServerKey{{KeyID: "prod", PublicKey: "AAAA"}}
	path := t.TempDir() + "/config.json"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.ServerKeys) != 1 || got.ServerKeys[0].KeyID != "prod" || got.DeviceID != cfg.DeviceID {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
