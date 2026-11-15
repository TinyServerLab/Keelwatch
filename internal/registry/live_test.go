package registry

import (
	"context"
	"os"
	"testing"
)

// Run with KEELWATCH_LIVE=1 to check real registries (needs internet).
func TestLiveRegistries(t *testing.T) {
	if os.Getenv("KEELWATCH_LIVE") == "" {
		t.Skip("set KEELWATCH_LIVE=1")
	}
	c := NewHTTPChecker()
	for _, ref := range []string{"nginx:1.25.3", "ghcr.io/linuxserver/jellyfin:10.9.11", "louislam/uptime-kuma:1"} {
		st := c.Check(context.Background(), ref, []string{"x@sha256:0000"})
		t.Logf("%s => err=%q digestNew=%v newest=%s bump=%s", ref, st.Error, st.DigestNew, st.NewestTag, st.Bump)
	}
}
