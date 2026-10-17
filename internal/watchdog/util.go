package watchdog

import (
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

func artifactOf(r update.Request) releasesig.Artifact {
	return releasesig.Artifact{SHA256: r.SHA256, Size: r.Size}
}
