//go:build windows

package peer

import (
	"time"
)

// markChannel zapamiętuje, czy kanał danych widza jest otwarty (do komunikatu o stanie wejścia), i loguje otwarcie (Info).
func (s *Session) markChannel(label string, open bool) {
	s.mu.Lock()
	if s.chanOpen == nil {
		s.chanOpen = map[string]bool{}
	}
	s.chanOpen[label] = open
	s.mu.Unlock()
	if open {
		s.log.Info("kanał danych otwarty", "channel", label)
	} else {
		s.log.Info("kanał danych zamknięty", "channel", label)
	}
}

// inputMessage buduje komunikat o stanie wejścia: liczniki drogi wejścia, kanały, weryfikacja DTLS i kontekst procesu.
func (s *Session) inputMessage() InputStatsMsg {
	m := s.inputStats.Snapshot()
	s.mu.Lock()
	m.Channels = map[string]bool{chanCtrl: s.chanOpen[chanCtrl], chanMouse: s.chanOpen[chanMouse], chanCursor: s.chanOpen[chanCursor], chanMeta: s.chanOpen[chanMeta]}
	s.mu.Unlock()
	m.DTLS = DTLSLabel(s.verdict())
	m.Control = s.o.Injector != nil
	if s.o.Probe != nil {
		m.Proc, m.FG = s.o.Probe()
	}
	return m
}

// inputStatsLoop co statsEvery wysyła widzowi kanałem meta stan wejścia, żeby widz sam pokazał, na którym etapie wejście ginie
// (przeglądarka → odebrane → odrzucone → wstrzyknięte → błędy SendInput), oraz raz loguje kontekst wstrzykiwania i ostrzega,
// gdy wejście dociera, a nic nie jest wstrzykiwane.
func (s *Session) inputStatsLoop(stop <-chan struct{}) {
	every := s.statsEvery
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	loggedCtx, warned := false, false
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		m := s.inputMessage()
		s.mu.Lock()
		dc := s.meta
		s.mu.Unlock()
		if dc != nil {
			s.sendJSON(dc, m)
		}
		if !loggedCtx && m.Proc != nil {
			loggedCtx = true
			s.log.Info("kontekst wstrzykiwania wejścia", "proc", m.Proc, "fg", m.FG, "control", m.Control)
		}
		if !warned && m.Control && m.Rx.Ctrl+m.Rx.Mouse >= 5 && m.Injected == 0 {
			warned = true
			s.log.Warn("wejście dociera, ale nic nie zostało wstrzyknięte", "rx_ctrl", m.Rx.Ctrl, "rx_mouse", m.Rx.Mouse, "rejected", m.Rejected,
				"errors", m.Errors, "last_error", m.LastError, "last_reject", m.LastReject, "dtls", m.DTLS, "proc", m.Proc, "fg", m.FG)
		}
	}
}
