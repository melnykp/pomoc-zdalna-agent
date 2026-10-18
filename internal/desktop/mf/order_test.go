//go:build windows

package mf

import "testing"

func TestOrderEncodersPrefersDisplayAdapterThenOtherHardwareThenSoftware(t *testing.T) {
	infos := []EncoderInfo{
		{Name: "NVIDIA H.264 Encoder MFT", Hardware: true, VendorID: "VEN_10DE"},
		{Name: "Intel Quick Sync Video H.264 Encoder MFT", Hardware: true, VendorID: "VEN_8086"},
		{Name: "H264 Encoder MFT", Hardware: false},
	}
	got, err := orderEncoders(infos, Config{Prefer: "auto", VendorID: 0x8086})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != infos[1].Name || got[1].Name != infos[0].Name || got[2].Name != infos[2].Name {
		t.Fatalf("kolejność: %v", names(got))
	}
	// Ścieżka GPU: tylko kodery karty wyświetlającej monitor.
	got, err = orderEncoders(infos, Config{VendorID: 0x8086, RequireVendor: true})
	if err != nil || len(got) != 1 || got[0].Name != infos[1].Name {
		t.Fatalf("GPU: %v %v", names(got), err)
	}
	if _, err := orderEncoders(infos, Config{VendorID: 0x1002, RequireVendor: true}); err == nil {
		t.Fatal("brak kodera AMD powinien dać błąd")
	}
	// Jawny wybór producenta zostaje jak dawniej.
	got, err = orderEncoders(infos, Config{Prefer: "software"})
	if err != nil || len(got) != 1 || got[0].Hardware {
		t.Fatalf("software: %v %v", names(got), err)
	}
}

func TestMatchesVendorUsesPCIFormat(t *testing.T) {
	e := EncoderInfo{VendorID: "VEN_8086"}
	if !e.MatchesVendor(0x8086) || e.MatchesVendor(0x10DE) || e.MatchesVendor(0) {
		t.Fatal("dopasowanie producenta")
	}
}

func names(in []EncoderInfo) []string {
	out := make([]string, len(in))
	for i, e := range in {
		out[i] = e.Name
	}
	return out
}
