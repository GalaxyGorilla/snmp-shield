// Package watchdog wraps the sd_notify protocol (systemd service
// awareness). When the gateway runs under systemd with WatchdogSec set,
// it announces readiness and pings WATCHDOG=1 so a wedged process is
// restarted by the host (the box IS the device's network path — it must
// never hang silently). Without systemd (no NOTIFY_SOCKET /
// WATCHDOG_USEC env) every function is a cheap no-op.
package watchdog

import (
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// Interval reports the systemd watchdog interval (WatchdogSec), or 0
// when the service does not run under a watchdog.
func Interval() time.Duration {
	d, err := daemon.SdWatchdogEnabled(false)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// NotifyReady sends READY=1 to systemd. Returns (false, nil) when not
// running under systemd.
func NotifyReady() (bool, error) {
	return daemon.SdNotify(false, daemon.SdNotifyReady)
}

// Start pings WATCHDOG=1 every interval/2 (systemd restarts the service
// when two intervals pass without a ping) until done is closed. Only
// call when Interval() > 0.
func Start(interval time.Duration, done <-chan struct{}) {
	tick := interval / 2
	if tick <= 0 {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
		}
	}
}
