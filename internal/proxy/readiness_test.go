package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"go.uber.org/zap"
)

// TestRunDoesNotAnnounceReadyBeforeBind pins the systemd contract: a
// listener bind failure must return an error without ever sending READY=1.
// Announcing readiness first would tell the host to route traffic to a
// process that is about to exit.
func TestRunDoesNotAnnounceReadyBeforeBind(t *testing.T) {
	// Keep the socket path short: macOS rejects unix socket paths over
	// ~104 bytes, and t.TempDir() under /var/folders can exceed that.
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("snmp-shield-notify-%d.sock", os.Getpid()))
	_ = os.Remove(sock)
	addr, err := net.ResolveUnixAddr("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	notify, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatalf("listen notify socket: %v", err)
	}
	defer func() {
		_ = notify.Close()
		_ = os.Remove(sock)
	}()
	t.Setenv("NOTIFY_SOCKET", sock)

	// Occupy the configured front port so the role's bind fails.
	front, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()

	cfg := &config.Config{Role: config.RoleGateway}
	cfg.Defaults()
	cfg.Security.Mode = "usm-gateway"
	cfg.Security.Users = testUsers()
	cfg.Security.EngineStore = filepath.Join(t.TempDir(), "engine.json")
	cfg.Gateway.ListenAddr = front.LocalAddr().String()
	cfg.Gateway.AgentAddr = "127.0.0.1:1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	opts := Options{Config: cfg, Log: zap.NewNop(), Version: "test"}
	opts.status = newStatusState(opts)
	if err := Run(opts); err == nil {
		t.Fatal("Run succeeded despite an occupied front port")
	}

	if err := notify.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	if n, _, rerr := notify.ReadFromUnix(buf); rerr == nil {
		t.Fatalf("READY was sent before every listener bound: %q", buf[:n])
	}
	if snap := opts.status.snapshot(); snap.ready["default"] {
		t.Fatal("status marked the default entry ready after a bind failure")
	}
}
