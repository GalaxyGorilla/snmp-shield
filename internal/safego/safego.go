// Package safego isolates a panic in one network handler from the rest of
// the process.
//
// snmp-shield parses attacker-controlled datagrams in long-lived goroutines.
// The decoders are fuzzed, but "no known crasher" is not the same as "no
// crasher": an unrecovered panic in a read loop takes down a proxy whose
// entire job is to stay between the network and a legacy device. So every
// per-datagram/per-session entry point runs under recover, which turns the
// panic into a loud error log (value + stack) and keeps serving.
//
// What it is NOT: a substitute for fixing the panic. A recovered panic is
// always a bug — the log entry is an error for a reason — and a panic in a
// goroutine spawned *inside* fn is not caught here (Go has no cross-goroutine
// recover); spawn those with Go, not `go`.
package safego

import (
	"runtime/debug"

	"go.uber.org/zap"
)

// Dispatch runs fn and converts a panic into a logged error.
//
// Use it around a single datagram or frame handler inside a read loop: the
// loop keeps serving, and the process survives. what names the site in the
// log ("usm gateway front request"), because the panic value alone rarely
// says which handler was reached.
func Dispatch(log *zap.Logger, what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			if log != nil {
				log.Error("recovered panic in "+what,
					zap.Any("panic", r),
					zap.ByteString("stack", debug.Stack()))
			}
		}
	}()
	fn()
}

// Go is Dispatch for a whole goroutine: a per-session server, a read loop.
// A panic ends that goroutine only — the session dies, the process does not.
func Go(log *zap.Logger, what string, fn func()) {
	go Dispatch(log, what, fn)
}
