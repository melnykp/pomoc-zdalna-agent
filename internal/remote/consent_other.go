//go:build !windows

package remote

import (
	"context"
	"errors"
)

// consentViaHelper poza Windows nie istnieje (silnik pulpitu działa tylko w Windows).
func (e *Engine) consentViaHelper(context.Context, ConsentRequest) (ConsentDecision, error) {
	return ConsentDenied, errors.New("okno zgody jest dostępne tylko w Windows")
}
