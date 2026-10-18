// Package runner to pętla główna agenta (docs/ARCHITECTURE.md): utrzymuje kanał z bramką,
// po handshake wysyła heartbeat i inwentaryzację, odbiera polecenia i odsyła wyniki. Po zerwaniu
// łączy się ponownie z wykładniczym odstępem, a odmowy serwera (oczekuje, zablokowany) obsługuje
// długimi przerwami zamiast zalewać bramkę próbami.
package runner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/commands"
	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/heartbeat"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/inventory"
	"github.com/melnykp/pomoc-zdalna-agent/internal/remote"
	"github.com/melnykp/pomoc-zdalna-agent/internal/session"
	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
	"github.com/melnykp/pomoc-zdalna-agent/internal/trust"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Options konfiguruje Runner. Pola funkcyjne podmienia się w testach.
type Options struct {
	Cfg      config.Config
	CfgPath  string // gdzie zapisać zmiany z config.set; pusty = nie zapisuj
	Identity *identity.Identity
	Log      *slog.Logger
	Versions wire.Versions

	Dial      func(ctx context.Context, url, deviceID string) (transport.Conn, error)
	Keys      func(cfg config.Config) ([]ed25519.PublicKey, error)
	Inventory func(ctx context.Context) (inventory.Inventory, error)
	Backoff   transport.Backoff
	// Update włącza aktualizacje; nil = agent ignoruje oferty wydań.
	Update *UpdateOptions

	// Remote to menedżer sesji pulpitu; nil = polecenia remote.* są odrzucane (moduł pulpitu wyłączony w tej wersji).
	Remote *remote.Manager
	// Helper instaluje pomocnika własnego silnika (komponent desktop_helper) niezależnie od włączonego silnika, żeby
	// przełączenie na własny silnik nie czekało na pobranie pliku; nil = oferty desktop_helper są odrzucane.
	Helper ComponentInstaller

	// OnRestart i OnRetire wywołuje runner po odesłaniu wyniku polecenia. Domyślnie nic nie robią.
	OnRestart func()
	OnRetire  func()

	// Czasy odmów. Zero oznacza wartości produkcyjne.
	MinPendingWait time.Duration
	BlockedWait    time.Duration
	RetiredWait    time.Duration
	RejectedWait   time.Duration
	UntrustedWait  time.Duration
}

// Runner utrzymuje połączenie z serwerem.
type Runner struct {
	o    Options
	log  *slog.Logger
	hb   *heartbeat.Collector
	disp *commands.Dispatcher

	cfgMu sync.RWMutex
	cfg   config.Config
	// cfgChanged budzi pętlę tickerów po config.set.
	cfgChanged chan struct{}

	connMu sync.RWMutex
	conn   transport.Conn

	// pending trzyma wyniki do czasu cmd.result.ack; po ponownym połączeniu odsyłamy je jeszcze raz.
	updMu     sync.Mutex
	modMu     sync.Mutex // instalacja klienta pulpitu (osobno od aktualizacji agenta)
	pendingMu sync.Mutex
	pending   map[string]wire.Envelope
}

// New tworzy Runner i rejestruje obsługę poleceń.
func New(o Options) *Runner {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Dial == nil {
		o.Dial = func(ctx context.Context, url, deviceID string) (transport.Conn, error) {
			return transport.Dial(ctx, transport.DialOptions{URL: url, DeviceID: deviceID})
		}
	}
	if o.Keys == nil {
		o.Keys = func(cfg config.Config) ([]ed25519.PublicKey, error) { return trust.Keys(cfg.ServerKeys) }
	}
	if o.Inventory == nil {
		o.Inventory = inventory.Collect
	}
	if o.Backoff.Min == 0 {
		o.Backoff = transport.DefaultBackoff()
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&o.MinPendingWait, 5*time.Second)
	def(&o.BlockedWait, 30*time.Minute)
	def(&o.RetiredWait, 6*time.Hour)
	def(&o.RejectedWait, 15*time.Minute)
	def(&o.UntrustedWait, 5*time.Minute)

	r := &Runner{
		o:          o,
		log:        o.Log,
		hb:         heartbeat.New(o.Versions),
		disp:       commands.New(60 * time.Second),
		cfg:        o.Cfg,
		cfgChanged: make(chan struct{}, 1),
		pending:    map[string]wire.Envelope{},
	}
	r.registerCommands()
	return r
}

// Config zwraca bieżącą konfigurację (po ewentualnym config.set).
func (r *Runner) Config() config.Config {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.cfg
}

// Run działa do anulowania ctx. Błędy połączenia nie kończą pętli.
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.Config()
	r.log.Info("agent start", "version", r.o.Versions.Agent, "server", cfg.ServerURL, "device_id", cfg.DeviceID, "ring", cfg.Ring)
	r.markStarted()
	r.startRemote(ctx)
	attempt := 0
	for ctx.Err() == nil {
		wait := r.connectOnce(ctx, &attempt)
		if err := sleep(ctx, wait); err != nil {
			break
		}
	}
	r.log.Info("agent stop")
	return nil
}

// startRemote zamyka dostęp pulpitu przy starcie (po awarii w trakcie sesji nie zostaje ważne hasło) i uruchamia obserwację sesji.
func (r *Runner) startRemote(ctx context.Context) {
	if r.o.Remote == nil {
		return
	}
	go func() {
		if err := r.o.Remote.Prepare(ctx); err != nil {
			r.log.Warn("przygotowanie modułu pulpitu nieudane", "err", err)
		}
		r.o.Remote.Run(ctx)
	}()
}

// SendRemoteState zgłasza serwerowi zmianę stanu sesji pulpitu (remote.state). Przy braku połączenia ponawia kilka razy:
// serwer i tak wygasza sesje po czasie, więc zgubiony stan nie zostawia sesji otwartej w panelu na zawsze.
func (r *Runner) SendRemoteState(sessionID, state string, stats *wire.RemoteStats) {
	go func() {
		msg := wire.RemoteState{SessionID: sessionID, State: state, At: time.Now().UnixMilli(), Stats: stats}
		for attempt := 0; attempt < 5; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			err := r.sendTyped(ctx, wire.TypeRemoteState, msg)
			cancel()
			if err == nil {
				return
			}
			time.Sleep(3 * time.Second)
		}
		r.log.Warn("nie udało się zgłosić stanu sesji pulpitu", "session_id", sessionID, "state", state)
	}()
}

// SendRemoteSignal przekazuje serwerowi sygnalizację WebRTC od pomocnika (kandydat ICE zebrany po odpowiedzi).
func (r *Runner) SendRemoteSignal(sig wire.RemoteSignal) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.sendTyped(ctx, wire.TypeRemoteSignal, sig); err != nil {
		r.log.Debug("sygnalizacja pulpitu niewysłana", "kind", sig.Kind, "err", err)
	}
}

// handleRemoteSignal obsługuje sygnalizację WebRTC od serwera (oferta albo kandydat widza): odpowiedź wraca tą samą
// wiadomością; błąd też, żeby panel nie czekał do końca limitu.
func (r *Runner) handleRemoteSignal(ctx context.Context, sig wire.RemoteSignal) {
	reply := func(out wire.RemoteSignal) {
		if err := r.sendTyped(ctx, wire.TypeRemoteSignal, out); err != nil {
			r.log.Warn("odpowiedź sygnalizacji pulpitu niewysłana", "err", err)
		}
	}
	if r.o.Remote == nil {
		reply(wire.RemoteSignal{SessionID: sig.SessionID, Kind: wire.SignalError, Error: "moduł pulpitu jest wyłączony w tej wersji agenta"})
		return
	}
	out, err := r.o.Remote.Signal(ctx, sig.SessionID, sig)
	switch {
	case errors.Is(err, remote.ErrNoSignaling):
		reply(wire.RemoteSignal{SessionID: sig.SessionID, Kind: wire.SignalError, Error: "ten komputer używa modułu pulpitu bez własnego silnika (RustDesk)"})
	case errors.Is(err, remote.ErrNoSession):
		reply(wire.RemoteSignal{SessionID: sig.SessionID, Kind: wire.SignalError, Error: "brak otwartej sesji pulpitu o tym identyfikatorze"})
	case errors.Is(err, remote.ErrNoUserSession):
		reply(wire.RemoteSignal{SessionID: sig.SessionID, Kind: wire.SignalError, Error: "nikt nie jest zalogowany na tym komputerze (ekran logowania nie jest jeszcze obsługiwany)"})
	case err != nil:
		r.log.Warn("sygnalizacja pulpitu nieudana", "kind", sig.Kind, "err", err)
		reply(wire.RemoteSignal{SessionID: sig.SessionID, Kind: wire.SignalError, Error: err.Error()})
	case out != nil:
		reply(*out)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// connectOnce wykonuje jedno podejście: dial, handshake, sesja. Zwraca czas do następnego podejścia.
func (r *Runner) connectOnce(ctx context.Context, attempt *int) time.Duration {
	cfg := r.Config()
	if cfg.DeviceID == "" {
		r.log.Error("brak device_id w konfiguracji: agent nie jest zarejestrowany")
		return r.o.RejectedWait
	}
	url, err := cfg.ChannelURL()
	if err != nil {
		r.log.Error("zły adres serwera", "err", err)
		return r.o.RejectedWait
	}
	keys, err := r.o.Keys(cfg)
	if err != nil {
		r.log.Error("brak zaufanych kluczy serwera", "err", err)
		return r.o.UntrustedWait
	}

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, err := r.o.Dial(dialCtx, url, cfg.DeviceID)
	cancel()
	if err != nil {
		*attempt++
		d := r.o.Backoff.Next(*attempt - 1)
		r.log.Warn("nie można połączyć się z serwerem", "err", err, "ponowna_proba_za", d.Round(time.Second))
		return d
	}

	hsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	info, err := session.Handshake(hsCtx, conn, session.Params{
		DeviceID:   cfg.DeviceID,
		Private:    r.o.Identity.Private,
		ServerKeys: keys,
		Versions:   r.versions(),
		Caps:       []string{"inventory", "commands"},
	})
	cancel()
	if err != nil {
		_ = conn.Close(1000, "handshake nieudany")
		return r.afterHandshakeError(err, attempt)
	}

	*attempt = 0
	r.log.Info("połączono z serwerem", "session_id", info.SessionID)
	err = r.serve(ctx, conn)
	if ctx.Err() != nil {
		return 0
	}
	r.log.Warn("połączenie zakończone", "err", err)
	// Krótka przerwa przed ponownym połączeniem; serwer, który często zamyka kanał, nie dostanie lawiny prób.
	return r.o.Backoff.Next(0)
}

func (r *Runner) afterHandshakeError(err error, attempt *int) time.Duration {
	var rej *session.RejectedError
	switch {
	case errors.As(err, &rej):
		*attempt = 0
		switch rej.Reason {
		case wire.AuthFailPending:
			wait := time.Duration(rej.RetryS) * time.Second
			if wait < r.o.MinPendingWait {
				wait = r.o.MinPendingWait
			}
			if wait > transport.PendingRetry {
				wait = transport.PendingRetry
			}
			r.log.Info("komputer czeka na zatwierdzenie przez inżyniera", "ponowna_proba_za", wait.Round(time.Second))
			return wait
		case wire.AuthFailBlocked:
			r.log.Warn("komputer jest zablokowany na serwerze", "ponowna_proba_za", r.o.BlockedWait)
			return r.o.BlockedWait
		case wire.AuthFailRetired:
			r.log.Warn("komputer został wycofany na serwerze", "ponowna_proba_za", r.o.RetiredWait)
			return r.o.RetiredWait
		default:
			r.log.Error("serwer odrzucił uwierzytelnienie", "powod", rej.Reason, "ponowna_proba_za", r.o.RejectedWait)
			return r.o.RejectedWait
		}
	case errors.Is(err, session.ErrUntrustedServer):
		r.log.Error("serwer nie przedstawił zaufanego podpisu; połączenie odrzucone", "ponowna_proba_za", r.o.UntrustedWait)
		return r.o.UntrustedWait
	default:
		*attempt++
		d := r.o.Backoff.Next(*attempt - 1)
		r.log.Warn("handshake nieudany", "err", err, "ponowna_proba_za", d.Round(time.Second))
		return d
	}
}

// serve obsługuje uwierzytelniony kanał do jego zakończenia.
func (r *Runner) serve(ctx context.Context, conn transport.Conn) error {
	sctx, cancel := context.WithCancel(ctx)
	r.setConn(conn)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		r.setConn(nil)
		_ = conn.Close(1000, "koniec sesji")
		wg.Wait()
	}()

	r.resendPending(sctx)

	errc := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errc <- r.readLoop(sctx, conn, &wg) }()
	go func() { defer wg.Done(); errc <- r.tickLoop(sctx, conn) }()
	return <-errc
}

func (r *Runner) setConn(c transport.Conn) {
	r.connMu.Lock()
	r.conn = c
	r.connMu.Unlock()
}

func (r *Runner) currentConn() transport.Conn {
	r.connMu.RLock()
	defer r.connMu.RUnlock()
	return r.conn
}

// send wysyła kopertę kanałem bieżącej sesji.
func (r *Runner) send(ctx context.Context, env wire.Envelope) error {
	c := r.currentConn()
	if c == nil {
		return errors.New("brak połączenia z serwerem")
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return c.Send(sctx, env)
}

func (r *Runner) sendTyped(ctx context.Context, t string, d any) error {
	env, err := wire.NewEnvelope(t, d)
	if err != nil {
		return err
	}
	return r.send(ctx, env)
}

func (r *Runner) tickLoop(ctx context.Context, conn transport.Conn) error {
	if err := r.sendHeartbeat(ctx); err != nil {
		return err
	}
	// Pierwszy heartbeat po udanym handshake to dowód, że ta wersja agenta działa i rozmawia z serwerem.
	r.onConnected(ctx)
	if err := r.sendInventory(ctx); err != nil {
		return err
	}
	if err := r.requestRelease(ctx); err != nil {
		return err
	}

	cfg := r.Config()
	hbT := time.NewTicker(time.Duration(cfg.HeartbeatSeconds) * time.Second)
	invT := time.NewTicker(time.Duration(cfg.InventoryHours) * time.Hour)
	pingT := time.NewTicker(transport.PingInterval)
	reqEvery := time.Hour
	if r.o.Update != nil {
		reqEvery = r.o.Update.requestEvery()
	}
	relT := time.NewTicker(reqEvery)
	resT := time.NewTicker(5 * time.Second)
	defer hbT.Stop()
	defer invT.Stop()
	defer pingT.Stop()
	defer relT.Stop()
	defer resT.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resT.C:
			r.reportUpdateResult(ctx)
		case <-relT.C:
			if err := r.requestRelease(ctx); err != nil {
				return err
			}
		case <-r.cfgChanged:
			cfg = r.Config()
			hbT.Reset(time.Duration(cfg.HeartbeatSeconds) * time.Second)
			invT.Reset(time.Duration(cfg.InventoryHours) * time.Hour)
		case <-hbT.C:
			if err := r.sendHeartbeat(ctx); err != nil {
				return err
			}
		case <-invT.C:
			if err := r.sendInventory(ctx); err != nil {
				return err
			}
		case <-pingT.C:
			pctx, cancel := context.WithTimeout(ctx, transport.PingTimeout)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return fmt.Errorf("brak odpowiedzi na ping: %w", err)
			}
		}
	}
}

func (r *Runner) sendHeartbeat(ctx context.Context) error {
	r.hb.SetVersions(r.versions())
	return r.sendTyped(ctx, wire.TypeHeartbeat, r.hb.Collect())
}

// versions zwraca wersje do raportu: wersja agenta z kompilacji i wersja watchdoga z jego znacznika w katalogu stanu
// (watchdog po aktualizacji agenta może być starszy, więc nie zakładamy, że jest taka sama).
func (r *Runner) versions() wire.Versions {
	v := r.o.Versions
	engine := r.Config().RemoteEngine
	if engine == "" {
		engine = config.RemoteEngineRustDesk
	}
	v.RemoteEngine = engine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Przy własnym silniku menedżer opakowuje pomocnika, więc jego wersja nie jest wersją klienta RustDesk.
	if r.o.Remote != nil && engine != config.RemoteEngineWebRTC {
		v.Remote = r.o.Remote.Version(ctx)
	}
	if r.o.Helper != nil {
		v.Helper = r.o.Helper.Version(ctx)
	}
	if r.o.Update != nil {
		if w, err := r.o.Update.Paths.ReadWatchdog(); err == nil {
			v.Watchdog = w.Version
		}
	}
	return v
}

func (r *Runner) sendInventory(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	inv, err := r.o.Inventory(cctx)
	cancel()
	if err != nil {
		// Nieudana inwentaryzacja nie psuje kanału; spróbujemy przy następnej okazji.
		r.log.Warn("inwentaryzacja nieudana", "err", err)
		return nil
	}
	return r.sendTyped(ctx, wire.TypeInventoryFull, inv)
}

func (r *Runner) readLoop(ctx context.Context, conn transport.Conn, wg *sync.WaitGroup) error {
	for {
		env, err := conn.Recv(ctx)
		if err != nil {
			return err
		}
		switch env.T {
		case wire.TypeCmd:
			var cmd wire.Cmd
			if err := env.Decode(&cmd); err != nil || cmd.CommandID == "" {
				r.log.Warn("nieprawidłowe polecenie od serwera", "err", err)
				continue
			}
			// Potwierdzenie odbioru idzie od razu, przed wykonaniem; serwer nie ponowi polecenia.
			if err := r.sendTyped(ctx, wire.TypeCmdAck, wire.CmdAck{CommandID: cmd.CommandID}); err != nil {
				return err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.runCommand(ctx, cmd)
			}()
		case wire.TypeCmdResultAck:
			var a wire.CmdResultAck
			if env.Decode(&a) == nil {
				r.pendingMu.Lock()
				delete(r.pending, a.CommandID)
				r.pendingMu.Unlock()
			}
		case wire.TypeReleaseAvailable:
			var offer wire.ReleaseAvailable
			if err := env.Decode(&offer); err != nil {
				r.log.Warn("nieprawidłowa oferta wydania od serwera", "err", err)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.handleOffer(ctx, offer)
			}()
		case wire.TypeRemoteSignal:
			var sig wire.RemoteSignal
			if err := env.Decode(&sig); err != nil || sig.SessionID == "" {
				r.log.Warn("nieprawidłowa sygnalizacja pulpitu od serwera", "err", err)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.handleRemoteSignal(ctx, sig)
			}()
		case wire.TypeError:
			var e wire.ErrorMsg
			_ = env.Decode(&e)
			r.log.Warn("serwer odrzucił wiadomość", "code", e.Code, "message", e.Message)
		default:
			r.log.Debug("pominięto wiadomość", "t", env.T)
		}
	}
}

func (r *Runner) runCommand(ctx context.Context, cmd wire.Cmd) {
	res, dup := r.disp.Execute(ctx, cmd, time.Now())
	if dup {
		r.log.Debug("powtórzone polecenie pominięte", "command_id", cmd.CommandID)
		return
	}
	env, err := wire.NewEnvelope(wire.TypeCmdResult, res)
	if err != nil {
		r.log.Error("nie można zbudować wyniku polecenia", "err", err)
		return
	}
	r.pendingMu.Lock()
	r.pending[cmd.CommandID] = env
	r.pendingMu.Unlock()
	if err := r.send(ctx, env); err != nil {
		r.log.Warn("wynik polecenia czeka na ponowne połączenie", "command_id", cmd.CommandID, "err", err)
	}
	r.log.Info("polecenie wykonane", "type", cmd.Type, "ok", res.OK, "ms", res.DurationMs)
}

// resendPending odsyła wyniki, których serwer nie potwierdził przed zerwaniem poprzedniego kanału.
func (r *Runner) resendPending(ctx context.Context) {
	r.pendingMu.Lock()
	envs := make([]wire.Envelope, 0, len(r.pending))
	for _, e := range r.pending {
		envs = append(envs, e)
	}
	r.pendingMu.Unlock()
	for _, e := range envs {
		if err := r.send(ctx, e); err != nil {
			return
		}
	}
}

func (r *Runner) registerCommands() {
	r.disp.Register(wire.CmdRemoteOpen, func(ctx context.Context, cmd wire.Cmd) (json.RawMessage, error) {
		if r.o.Remote == nil {
			return nil, errors.New("moduł pulpitu jest wyłączony w tej wersji agenta")
		}
		var p wire.RemoteOpenPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil || p.SessionID == "" {
			return nil, fmt.Errorf("zły ładunek remote.open: %v", err)
		}
		sess, err := r.o.Remote.Open(ctx, p.SessionID, time.Duration(p.TTLS)*time.Second)
		switch {
		case errors.Is(err, remote.ErrNotInstalled):
			return nil, errors.New("na tym komputerze nie ma jeszcze modułu pulpitu")
		case errors.Is(err, remote.ErrBusy):
			return nil, errors.New("na tym komputerze trwa już inna sesja pulpitu")
		case err != nil:
			return nil, err
		}
		// Hasło jednorazowe idzie osobną wiadomością, nigdy w wyniku polecenia (wynik trafia do bazy serwera).
		otp := wire.RemoteOTP{SessionID: sess.ID, RemoteID: sess.RemoteID, OTP: sess.OTP, ExpiresAt: sess.ExpiresAt.UnixMilli(), Engine: sess.Engine}
		if err := r.sendTyped(ctx, wire.TypeRemoteOTP, otp); err != nil {
			_ = r.o.Remote.Close(ctx, sess.ID)
			return nil, fmt.Errorf("nie udało się przekazać hasła sesji serwerowi: %w", err)
		}
		return json.RawMessage(`{"opened":true}`), nil
	})

	r.disp.Register(wire.CmdRemoteClose, func(ctx context.Context, cmd wire.Cmd) (json.RawMessage, error) {
		if r.o.Remote == nil {
			return nil, errors.New("moduł pulpitu jest wyłączony w tej wersji agenta")
		}
		var p wire.RemoteClosePayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return nil, fmt.Errorf("zły ładunek remote.close: %v", err)
		}
		if err := r.o.Remote.Close(ctx, p.SessionID); err != nil && !errors.Is(err, remote.ErrNoSession) {
			return nil, err
		}
		return json.RawMessage(`{"closed":true}`), nil
	})

	r.disp.Register(wire.CmdInventoryRefresh, func(ctx context.Context, _ wire.Cmd) (json.RawMessage, error) {
		if err := r.sendInventory(ctx); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"sent":true}`), nil
	})

	r.disp.Register(wire.CmdUpdateCheck, func(ctx context.Context, _ wire.Cmd) (json.RawMessage, error) {
		if r.o.Update == nil {
			return nil, errors.New("aktualizacje są wyłączone w tej wersji agenta")
		}
		if err := r.requestRelease(ctx); err != nil {
			return nil, err
		}
		// Oferta przychodzi osobną wiadomością i jest rozpatrywana asynchronicznie.
		return json.RawMessage(`{"requested":true}`), nil
	})

	r.disp.Register(wire.CmdAgentRestart, func(context.Context, wire.Cmd) (json.RawMessage, error) {
		if r.o.OnRestart != nil {
			if r.o.Update != nil {
				_ = r.o.Update.Paths.MarkIntentionalRestart()
			}
			// Opóźnienie daje czas na odesłanie wyniku, zanim proces się zakończy.
			time.AfterFunc(2*time.Second, r.o.OnRestart)
		}
		return json.RawMessage(`{"restarting":true}`), nil
	})

	r.disp.Register(wire.CmdDeviceRetire, func(context.Context, wire.Cmd) (json.RawMessage, error) {
		if r.o.OnRetire != nil {
			time.AfterFunc(3*time.Second, r.o.OnRetire)
		}
		return json.RawMessage(`{"retiring":true}`), nil
	})

	r.disp.Register(wire.CmdConfigSet, func(_ context.Context, cmd wire.Cmd) (json.RawMessage, error) {
		var p wire.ConfigSetPayload
		if err := json.Unmarshal(cmd.Payload, &p); err != nil {
			return nil, fmt.Errorf("zły ładunek config.set: %w", err)
		}
		return r.applyConfig(p)
	})
}

// applyConfig waliduje i zapisuje zmiany ustawień; nieprawidłowe wartości odrzuca w całości.
func (r *Runner) applyConfig(p wire.ConfigSetPayload) (json.RawMessage, error) {
	r.cfgMu.Lock()
	next := r.cfg
	if p.HeartbeatS != nil {
		next.HeartbeatSeconds = *p.HeartbeatS
	}
	if p.InventoryH != nil {
		next.InventoryHours = *p.InventoryH
	}
	if p.Whitelist != nil {
		next.Whitelist = p.Whitelist
	}
	if p.RemoteEngine != nil {
		next.RemoteEngine = *p.RemoteEngine
	}
	if err := next.Validate(); err != nil {
		r.cfgMu.Unlock()
		return nil, err
	}
	if r.o.CfgPath != "" {
		if err := config.Save(r.o.CfgPath, next); err != nil {
			r.cfgMu.Unlock()
			return nil, fmt.Errorf("zapis konfiguracji: %w", err)
		}
	}
	r.cfg = next
	r.cfgMu.Unlock()

	select {
	case r.cfgChanged <- struct{}{}:
	default:
	}
	return json.Marshal(map[string]any{"heartbeat_s": next.HeartbeatSeconds, "inventory_h": next.InventoryHours, "whitelist": len(next.Whitelist), "remote_engine": next.RemoteEngine})
}
