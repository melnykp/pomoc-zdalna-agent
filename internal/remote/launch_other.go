//go:build !windows

package remote

import (
	"context"
	"log/slog"
)

// launchHelper poza Windows uruchamia pomocnika jako proces potomny (tylko do testów; silnik działa w Windows).
func launchHelper(ctx context.Context, exe string, log *slog.Logger, _ string, _ func(TokenChoice)) (Process, error) {
	return launchChild(ctx, exe, log)
}

// runningAsSystem poza Windows nigdy nie jest prawdą (nie ma usługi SYSTEM).
func runningAsSystem() bool { return false }
