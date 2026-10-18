//go:build windows

package engine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/com"
)

func TestTransientOpenErrorClassifiesDXGIFailures(t *testing.T) {
	cases := []struct {
		hr   com.HRESULT
		want bool
		name string
	}{
		{0x80070005, true, "E_ACCESSDENIED"},
		{0x887A0022, true, "NOT_CURRENTLY_AVAILABLE"},
		{0x887A0026, true, "ACCESS_LOST"},
		{0x887A0028, true, "SESSION_DISCONNECTED"},
		{0x887A0004, false, "UNSUPPORTED"},
		{0x887A0005, false, "DEVICE_REMOVED"},
	}
	for _, c := range cases {
		// Tak błąd wychodzi z capture: DuplicateOutput owija HRESULT przez %w, a retryOpen dokłada kolejne warstwy.
		err := fmt.Errorf("duplikacja: %w", fmt.Errorf("DuplicateOutput: %w", c.hr))
		if got := transientOpenError(err); got != c.want {
			t.Errorf("%s: transient=%v, oczekiwano %v", c.name, got, c.want)
		}
	}
	// Błąd bez HRESULT (np. nieznana awaria) jest ponawiany; kilka prób nie szkodzi.
	if !transientOpenError(errors.New("coś innego")) {
		t.Error("nieznany błąd powinien być ponawiany")
	}
}

func TestPathInfoReportsDegradedOnlyForGDI(t *testing.T) {
	e := New(Config{}, nil)
	var got []PathInfo
	e.SetOnPath(func(p PathInfo) { got = append(got, p) })
	e.setReason("duplikacja: DuplicateOutput: HRESULT 0x80070005")
	e.setInfo("Intel", PathGDI, 1920, 1200, 30)
	e.setInfo("Intel", PathGDI, 1920, 1200, 30) // bez zmiany: bez powtórnego zgłoszenia
	e.setInfo("Intel", PathGPU, 1920, 1200, 60)
	if len(got) != 2 {
		t.Fatalf("zgłoszeń: %d (%+v)", len(got), got)
	}
	if !got[0].Degraded || got[0].Path != PathGDI || got[0].Reason == "" {
		t.Fatalf("GDI: %+v", got[0])
	}
	if got[1].Degraded || got[1].Reason != "" || got[1].Path != PathGPU {
		t.Fatalf("GPU: %+v", got[1])
	}
	if e.Path() != got[1] {
		t.Fatalf("Path() = %+v", e.Path())
	}
}
