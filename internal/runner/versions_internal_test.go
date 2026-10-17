package runner

import (
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

func TestVersionsIncludeWatchdogVersionFromItsMarker(t *testing.T) {
	paths := update.Paths{Root: t.TempDir()}
	r := &Runner{o: Options{Versions: wire.Versions{Agent: "1.3.0"}, Update: &UpdateOptions{Paths: paths}}}

	if v := r.versions(); v.Agent != "1.3.0" || v.Watchdog != "" {
		t.Fatalf("bez znacznika watchdog powinien być pusty: %+v", v)
	}
	if err := paths.WriteWatchdog(update.WatchdogInfo{Version: "1.2.0", PID: 1, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if v := r.versions(); v.Agent != "1.3.0" || v.Watchdog != "1.2.0" {
		t.Fatalf("wersje powinny zawierać watchdoga ze znacznika: %+v", v)
	}
}
