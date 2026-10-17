package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

// Paths wskazuje katalogi wymiany danych między agentem a watchdogiem. Oba procesy działają jako SYSTEM,
// a katalog danych jest dostępny tylko dla SYSTEM i Administratorów (svc.SecureDir), więc zwykłe pliki w nim
// zastępują potok nazwany: nikt spoza tej granicy zaufania nie może podrzucić prośby o podmianę pliku.
type Paths struct{ Root string }

// Staging to miejsce na pobrane, zweryfikowane pliki czekające na podmianę.
func (p Paths) Staging() string { return filepath.Join(p.Root, "staging") }

// State to katalog plików stanu aktualizacji.
func (p Paths) State() string { return filepath.Join(p.Root, "state") }

func (p Paths) requestFile() string { return filepath.Join(p.State(), "update-request.json") }
func (p Paths) resultFile() string  { return filepath.Join(p.State(), "update-result.json") }
func (p Paths) healthFile() string  { return filepath.Join(p.State(), "health.json") }
func (p Paths) startsFile() string  { return filepath.Join(p.State(), "starts.log") }
func (p Paths) badFile() string     { return filepath.Join(p.State(), "bad-releases.json") }

// Request to prośba agenta do watchdoga o podmianę pliku. Watchdog nie ufa jej: sprawdza podpis sshsig dołączonego
// manifestu (kluczami wkompilowanymi w plik), zgodność prośby z manifestem, a potem sumę, rozmiar i Authenticode pliku
// ze staging według manifestu. Dzięki temu ktoś, kto zapisze prośbę w katalogu stanu, nie podstawi własnego pliku.
type Request struct {
	ReleaseID           string `json:"release_id"`
	Component           string `json:"component"`
	Version             string `json:"version"`
	FromVersion         string `json:"from_version"`
	Path                string `json:"path"`
	SHA256              string `json:"sha256"`
	Size                int64  `json:"size"`
	AuthenticodeSubject string `json:"authenticode_subject"`
	// Manifest i Signature to oferta wydania dokładnie tak, jak ją podpisano (tekst manifestu i podpis sshsig).
	Manifest    string    `json:"manifest"`
	Signature   string    `json:"signature"`
	RequestedAt time.Time `json:"requested_at"`
}

// Stany wyniku aktualizacji (zgodne ze stanami w wire.UpdateStatus).
const (
	StateSuccess    = "success"
	StateRolledBack = "rolled_back"
	StateFailed     = "failed"
)

// Result to wynik podmiany zapisany przez watchdoga. Agent odczytuje go po starcie i zgłasza serwerowi.
type Result struct {
	ReleaseID   string    `json:"release_id"`
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	At          time.Time `json:"at"`
}

// Fazy zdrowia agenta po starcie.
const (
	// PhaseStarted: proces wystartował, wczytał konfigurację i tożsamość.
	PhaseStarted = "started"
	// PhaseConnected: agent przeszedł handshake z serwerem i wysłał pierwszy heartbeat.
	PhaseConnected = "connected"
)

// Health to znacznik życia agenta po starcie. Watchdog czeka na fazę „connected” z oczekiwaną wersją.
type Health struct {
	Version string    `json:"version"`
	Phase   string    `json:"phase"`
	PID     int       `json:"pid"`
	At      time.Time `json:"at"`
}

var fileMu sync.Mutex

// writeJSON zapisuje plik atomowo: plik tymczasowy, potem zmiana nazwy.
func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// ErrNone oznacza brak pliku (brak prośby, wyniku albo znacznika zdrowia).
var ErrNone = errors.New("update: brak pliku")

func readOptional(path string, v any) error {
	if err := readJSON(path, v); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNone
		}
		return err
	}
	return nil
}

func remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// WriteRequest zapisuje prośbę o podmianę. Istniejąca, niewykonana prośba jest nadpisywana.
func (p Paths) WriteRequest(r Request) error { return writeJSON(p.requestFile(), r) }

// ReadRequest odczytuje prośbę; ErrNone, gdy jej nie ma.
func (p Paths) ReadRequest() (Request, error) {
	var r Request
	return r, readOptional(p.requestFile(), &r)
}

// RemoveRequest usuwa prośbę.
func (p Paths) RemoveRequest() error { return remove(p.requestFile()) }

// WriteResult zapisuje wynik podmiany.
func (p Paths) WriteResult(r Result) error { return writeJSON(p.resultFile(), r) }

// ReadResult odczytuje wynik; ErrNone, gdy go nie ma.
func (p Paths) ReadResult() (Result, error) {
	var r Result
	return r, readOptional(p.resultFile(), &r)
}

// RemoveResult usuwa wynik po zgłoszeniu go serwerowi.
func (p Paths) RemoveResult() error { return remove(p.resultFile()) }

// WriteHealth zapisuje znacznik życia.
func (p Paths) WriteHealth(h Health) error { return writeJSON(p.healthFile(), h) }

// ReadHealth odczytuje znacznik życia; ErrNone, gdy go nie ma.
func (p Paths) ReadHealth() (Health, error) {
	var h Health
	return h, readOptional(p.healthFile(), &h)
}

// RemoveHealth usuwa znacznik życia (watchdog robi to przed startem nowej wersji).
func (p Paths) RemoveHealth() error { return remove(p.healthFile()) }

// maxBad ogranicza listę odrzuconych wydań.
const maxBad = 50

// MarkBad zapamiętuje wydanie, które po podmianie nie przeszło (rollback). Agent nie próbuje go ponownie.
func (p Paths) MarkBad(releaseID string) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	ids, _ := p.badLocked()
	for _, id := range ids {
		if id == releaseID {
			return nil
		}
	}
	ids = append(ids, releaseID)
	if len(ids) > maxBad {
		ids = ids[len(ids)-maxBad:]
	}
	return writeJSON(p.badFile(), ids)
}

// IsBad mówi, czy wydanie zostało wcześniej odrzucone na tym komputerze.
func (p Paths) IsBad(releaseID string) bool {
	fileMu.Lock()
	defer fileMu.Unlock()
	ids, _ := p.badLocked()
	for _, id := range ids {
		if id == releaseID {
			return true
		}
	}
	return false
}

func (p Paths) badLocked() ([]string, error) {
	var ids []string
	err := readOptional(p.badFile(), &ids)
	if errors.Is(err, ErrNone) {
		return nil, nil
	}
	return ids, err
}

// RecordStart dopisuje znacznik startu agenta; watchdog z niego liczy restarty w oknie czasu.
func (p Paths) RecordStart(now time.Time) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if err := os.MkdirAll(p.State(), 0o700); err != nil {
		return err
	}
	starts := p.readStartsLocked()
	starts = append(starts, now)
	if len(starts) > 50 {
		starts = starts[len(starts)-50:]
	}
	var sb strings.Builder
	for _, t := range starts {
		sb.WriteString(strconv.FormatInt(t.Unix(), 10))
		sb.WriteByte('\n')
	}
	tmp := p.startsFile() + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.startsFile())
}

// StartsSince zwraca liczbę startów agenta od podanej chwili.
func (p Paths) StartsSince(since time.Time) int {
	fileMu.Lock()
	defer fileMu.Unlock()
	n := 0
	for _, t := range p.readStartsLocked() {
		if !t.Before(since) {
			n++
		}
	}
	return n
}

// ClearStarts czyści znaczniki startów (po udanej aktualizacji albo rollbacku zaczynamy liczyć od zera).
func (p Paths) ClearStarts() error {
	fileMu.Lock()
	defer fileMu.Unlock()
	return remove(p.startsFile())
}

func (p Paths) readStartsLocked() []time.Time {
	raw, err := os.ReadFile(p.startsFile())
	if err != nil {
		return nil
	}
	var out []time.Time
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if n, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64); err == nil {
			out = append(out, time.Unix(n, 0))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// String ułatwia logowanie prośby.
func (r Request) String() string {
	return fmt.Sprintf("%s %s → %s (%s)", r.Component, r.FromVersion, r.Version, r.ReleaseID)
}

// LastUpdate opisuje ostatnią udaną podmianę. Dopóki poprzednia wersja (.prev) leży obok, watchdog może do niej
// wrócić, gdy nowa zacznie się wykrzaczać po dłuższym czasie.
type LastUpdate struct {
	ReleaseID   string    `json:"release_id"`
	Version     string    `json:"version"`
	FromVersion string    `json:"from_version"`
	At          time.Time `json:"at"`
}

func (p Paths) lastUpdateFile() string { return filepath.Join(p.State(), "last-update.json") }

// WriteLastUpdate zapisuje dane ostatniej udanej podmiany.
func (p Paths) WriteLastUpdate(u LastUpdate) error { return writeJSON(p.lastUpdateFile(), u) }

// ReadLastUpdate odczytuje dane ostatniej podmiany; ErrNone, gdy jej nie było albo już ją rozliczono.
func (p Paths) ReadLastUpdate() (LastUpdate, error) {
	var u LastUpdate
	return u, readOptional(p.lastUpdateFile(), &u)
}

// RemoveLastUpdate zamyka okno rollbacku z powodu awarii.
func (p Paths) RemoveLastUpdate() error { return remove(p.lastUpdateFile()) }

func (p Paths) floorFile() string { return filepath.Join(p.State(), "security-floor.json") }

type floorRecord struct {
	MinVersion string    `json:"min_version"`
	At         time.Time `json:"at"`
}

// Floor zwraca zapamiętany próg bezpieczeństwa (najniższą wersję, jaką wolno zainstalować) albo "".
func (p Paths) Floor() string {
	fileMu.Lock()
	defer fileMu.Unlock()
	var r floorRecord
	if err := readOptional(p.floorFile(), &r); err != nil {
		return ""
	}
	return r.MinVersion
}

// RaiseFloor podnosi próg do v, jeśli v jest wyższe od zapamiętanego. Próg nigdy nie maleje, więc nawet przejęty
// serwer nie cofnie go ofertą starego, podpisanego manifestu.
func (p Paths) RaiseFloor(v string) error {
	if v == "" {
		return nil
	}
	fileMu.Lock()
	defer fileMu.Unlock()
	var cur floorRecord
	if err := readOptional(p.floorFile(), &cur); err == nil && cur.MinVersion != "" {
		c, cerr := releasesig.CompareVersions(v, cur.MinVersion)
		if cerr != nil {
			return cerr
		}
		if c <= 0 {
			return nil
		}
	}
	return writeJSON(p.floorFile(), floorRecord{MinVersion: v, At: time.Now().UTC()})
}

// WatchdogInfo to znacznik nadzorcy: jego wersja i czas ostatniego zapisu. Agent czyta go, żeby zgłaszać serwerowi
// wersję watchdoga (to ten sam plik, ale po aktualizacji agenta nadzorca może być starszy).
type WatchdogInfo struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	At      time.Time `json:"at"`
}

func (p Paths) watchdogFile() string { return filepath.Join(p.State(), "watchdog.json") }

// WriteWatchdog zapisuje znacznik nadzorcy.
func (p Paths) WriteWatchdog(w WatchdogInfo) error { return writeJSON(p.watchdogFile(), w) }

// ReadWatchdog odczytuje znacznik nadzorcy; ErrNone, gdy go nie ma.
func (p Paths) ReadWatchdog() (WatchdogInfo, error) {
	var w WatchdogInfo
	return w, readOptional(p.watchdogFile(), &w)
}

func (p Paths) intentionalRestartFile() string {
	return filepath.Join(p.State(), "intentional-restart")
}

// MarkIntentionalRestart zapisuje, że zbliżający się restart agenta jest zamierzony (polecenie agent.restart). Zamierzony
// restart nie liczy się do pętli awarii, więc nikt nie wymusi rollbacku samymi poleceniami restartu.
func (p Paths) MarkIntentionalRestart() error {
	if err := os.MkdirAll(p.State(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.intentionalRestartFile(), []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0o600)
}

// ConsumeIntentionalRestart zwraca true i usuwa znacznik, gdy poprzedni proces zakończył się zamierzonym restartem
// (znacznik starszy niż 5 minut jest ignorowany).
func (p Paths) ConsumeIntentionalRestart(now time.Time) bool {
	raw, err := os.ReadFile(p.intentionalRestartFile())
	if err != nil {
		return false
	}
	_ = os.Remove(p.intentionalRestartFile())
	sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return false
	}
	return now.Sub(time.Unix(sec, 0)) < 5*time.Minute
}
