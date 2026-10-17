package passthrough

import (
	"testing"
	"time"
)

// reqCtx/trapCtx: verify the shared base context cancels on stop.
func TestManagerBaseCtxCancelsOnStop(t *testing.T) {
	m := &Manager{stop: make(chan struct{})}
	ctx := m.reqCtx()
	select {
	case <-ctx.Done():
		t.Fatal("context must not be cancelled before stop")
	default:
	}
	close(m.stop)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Millisecond)
		}
	}
	t.Fatal("context was not cancelled after stop")
}
