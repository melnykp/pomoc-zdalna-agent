//go:build windows

package peer

import (
	"strings"
	"time"
)

// Parametry oczekiwania na certyfikat DTLS widza. Certyfikat zdalny bywa dostępny chwilę po tym, jak kanał danych się
// otworzy albo połączenie zgłosi stan connected, więc brak certyfikatu NIE jest rozstrzygnięciem: handlery kanałów są
// rejestrowane zawsze, a bramka weryfikacji stoi w chwili użycia (wejście) albo przed ustawieniem kanału (kursor, meta).
const (
	defaultVerifyPoll = 200 * time.Millisecond
	// verifyChannelWait to czas, przez jaki kanał kursora/meta czeka na certyfikat, zanim zrezygnuje (połączenie i tak zamyka
	// pętla stanu połączenia po verifyConnectPolls próbach).
	verifyChannelWait   = 5 * time.Second
	verifyConnectPolls  = 25
	verifyRejectLogEach = time.Second
)

// pionRemoteCert zwraca certyfikat DTLS (DER) drugiej strony albo nil, dopóki handshake go nie udostępnił.
func (s *Session) pionRemoteCert() []byte {
	if s.pc == nil {
		return nil
	}
	if sctp := s.pc.SCTP(); sctp != nil && sctp.Transport() != nil {
		return sctp.Transport().GetRemoteCertificate()
	}
	return nil
}

// verdict zwraca rozstrzygnięcie weryfikacji: 0 = jeszcze nie ma, 1 = zgodny, -1 = niezgodny.
func (s *Session) verdict() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verified
}

func (s *Session) isEnded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ended
}

// verifyRemote porównuje (raz) certyfikat DTLS drugiej strony z odciskiem z oferty (i przypiętym przez serwer).
// true = zgodny, wolno kontynuować; false = niezgodny (wtedy sesja jest zamykana) albo certyfikatu jeszcze nie ma
// (rozstrzygnięcie zapada przy kolejnej próbie). Wynik loguje na poziomie Info.
func (s *Session) verifyRemote() bool {
	s.mu.Lock()
	if s.verified != 0 {
		ok := s.verified > 0
		s.mu.Unlock()
		return ok
	}
	want := s.remoteFP
	s.mu.Unlock()
	der := s.remoteCert()
	if len(der) == 0 {
		return false
	}
	got := CertificateFingerprint(der)
	s.mu.Lock()
	if s.verified != 0 { // wyścig dwóch wywołań: decyduje pierwsze
		ok := s.verified > 0
		s.mu.Unlock()
		return ok
	}
	ok := want != "" && strings.EqualFold(got, want)
	if ok {
		s.verified = 1
	} else {
		s.verified = -1
	}
	s.mu.Unlock()
	if ok {
		s.log.Info("weryfikacja DTLS: certyfikat widza zgodny z odciskiem sesji", "fingerprint", got)
		return true
	}
	s.log.Error("weryfikacja DTLS: certyfikat widza NIEZGODNY z odciskiem sesji, zamykam", "want", want, "got", got)
	s.failVerification()
	return false
}

// failVerification zamyka sesję po niezgodnym odcisku (idempotentne; wołane przez każdego, kto zobaczy verdict == -1).
func (s *Session) failVerification() {
	s.end(StateFailed)
	if s.pc != nil {
		_ = s.pc.Close()
	}
}

// whenVerified wykonuje fn, gdy certyfikat widza będzie zgodny z przypiętym odciskiem: od razu, jeśli weryfikacja już
// przeszła, inaczej po jej przejściu (próby co verifyPoll przez ok. 5 s). Przy niezgodności fn nie jest wołane, a sesja
// zamykana. what opisuje kanał w logach.
func (s *Session) whenVerified(what string, fn func()) {
	if s.verifyRemote() {
		fn()
		return
	}
	if s.verdict() < 0 {
		return
	}
	poll := s.verifyPoll
	if poll <= 0 {
		poll = defaultVerifyPoll
	}
	go func() {
		deadline := time.Now().Add(verifyChannelWait)
		for time.Now().Before(deadline) {
			time.Sleep(poll)
			if s.isEnded() {
				return
			}
			if s.verifyRemote() {
				s.log.Info("kanał danych uruchomiony po weryfikacji DTLS", "channel", what)
				fn()
				return
			}
			if s.verdict() < 0 {
				s.failVerification() // deterministycznie, także gdy rozstrzygnął ktoś inny
				return
			}
		}
		s.log.Warn("kanał danych nie został uruchomiony: brak certyfikatu DTLS widza w czasie", "channel", what, "wait", verifyChannelWait.String())
	}()
}

// onChannelMessage to wejście z kanałów ctrl i mouse: ramki są odrzucane (z logiem), dopóki weryfikacja DTLS nie przejdzie,
// a po przejściu działają na tym samym kanale, bez ponownego otwierania.
func (s *Session) onChannelMessage(label string, raw []byte) {
	if label == chanMouse {
		s.inputStats.RxMouse.Add(1)
	} else {
		s.inputStats.RxCtrl.Add(1)
	}
	if s.inputOff.Load() {
		s.rejectInput(label, "sesja zakończona")
		return
	}
	if !s.verifyRemote() {
		if s.verdict() < 0 {
			s.rejectInput(label, "certyfikat DTLS widza niezgodny z odciskiem sesji")
			s.failVerification()
		} else {
			s.rejectInput(label, "certyfikat DTLS widza jeszcze niedostępny, wejście odrzucone do czasu weryfikacji")
		}
		return
	}
	s.onInput(raw)
}

// rejectInput loguje odrzucone wejście: pierwsze od razu (Info), potem najwyżej raz na sekundę z licznikiem pominiętych.
func (s *Session) rejectInput(label, reason string) {
	if s.inputStats != nil {
		s.inputStats.NoteReject(reason)
	}
	if s.rejectLog == nil {
		return
	}
	if ok, sup := s.rejectLog.allow(); ok {
		s.log.Info("wejście odrzucone", "channel", label, "reason", reason, "suppressed", sup)
	}
}

// logInputError loguje błąd wstrzykiwania (SendInput) jako Warn, najwyżej raz na sekundę.
func (s *Session) logInputError(t string, err error) {
	if s.sendLog == nil {
		return
	}
	if ok, sup := s.sendLog.allow(); ok {
		s.log.Warn("wstrzykiwanie wejścia nieudane", "t", t, "err", err, "suppressed", sup)
	}
}

// verifyThenStart czeka (do verifyConnectPolls prób co verifyPoll) na certyfikat DTLS widza po stanie connected i dopiero
// po zgodnej weryfikacji uruchamia silnik. Niezgodność i brak certyfikatu w czasie zamykają połączenie.
func (s *Session) verifyThenStart() {
	poll := s.verifyPoll
	if poll <= 0 {
		poll = defaultVerifyPoll
	}
	for i := 0; i < verifyConnectPolls; i++ {
		if s.verifyRemote() {
			s.start()
			return
		}
		if s.verdict() < 0 {
			s.failVerification() // verifyRemote już zamknął, ale nie polegamy na tym, kto rozstrzygnął
			return
		}
		if s.isEnded() {
			return
		}
		time.Sleep(poll)
	}
	s.log.Error("weryfikacja DTLS: brak certyfikatu widza po połączeniu, zamykam", "polls", verifyConnectPolls, "poll", poll.String())
	s.failVerification()
}
