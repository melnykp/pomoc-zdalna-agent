// Package enroll rejestruje urządzenie na serwerze z linku zaproszenia (docs/ARCHITECTURE.md).
package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
)

// Request to ciało POST /v1/enroll.
type Request struct {
	InvitationToken string `json:"invitation_token"`
	PublicKey       string `json:"public_key"`
	Hostname        string `json:"hostname"`
	OSFamily        string `json:"os_family"`
	OSVersion       string `json:"os_version,omitempty"`
	Arch            string `json:"arch"`
	HwID            string `json:"hw_id,omitempty"`
	AgentVersion    string `json:"agent_version"`
}

// Response to odpowiedź serwera.
type Response struct {
	DeviceID   string             `json:"device_id"`
	Status     string             `json:"status"`
	WSURL      string             `json:"ws_url"`
	ServerKeys []config.ServerKey `json:"server_keys"`
	ShortCode  string             `json:"short_code"`
}

// Error to odmowa serwera z kodem do pokazania człowiekowi.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("rejestracja odrzucona (%d %s): %s", e.Status, e.Code, e.Message)
}

// Codes z serwera, które mają sens dla człowieka.
const (
	CodeInvalidInvitation = "enrollment_invalid"
	CodeAlreadyEnrolled   = "already_enrolled"
)

// Do wysyła rejestrację na serwerBase (np. https://agent.example.pl). Client może być nil.
func Do(ctx context.Context, client *http.Client, serverBase string, req Request) (Response, error) {
	if client == nil {
		client = transport.NewHTTPClient(30 * time.Second)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(serverBase, "/")+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "rmm-agent")

	res, err := client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("enroll: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return Response{}, fmt.Errorf("enroll: odczyt odpowiedzi: %w", err)
	}

	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		var e struct {
			Code    string `json:"code"`
			Message any    `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg, _ := e.Message.(string)
		if msg == "" {
			msg = res.Status
		}
		return Response{}, &Error{Status: res.StatusCode, Code: e.Code, Message: msg}
	}

	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return Response{}, fmt.Errorf("enroll: zła odpowiedź serwera: %w", err)
	}
	if out.DeviceID == "" {
		return Response{}, errors.New("enroll: odpowiedź bez device_id")
	}
	return out, nil
}

// Explain tłumaczy błąd rejestracji na komunikat dla klienta końcowego.
func Explain(err error) string {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case CodeInvalidInvitation:
			return "Ten link wygasł albo został już wykorzystany. Poproś osobę, która go przysłała, o nowy."
		case CodeAlreadyEnrolled:
			return "Ten komputer jest już zarejestrowany."
		}
		if e.Status == http.StatusTooManyRequests {
			return "Za dużo prób. Poczekaj chwilę i uruchom program ponownie."
		}
		return "Serwer odrzucił rejestrację. Skontaktuj się z osobą, która przysłała link."
	}
	return "Nie udało się połączyć z serwerem. Sprawdź połączenie z internetem i spróbuj ponownie."
}
