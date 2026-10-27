// reload.go: SIGHUP re-reads the YAML file and applies the parts of the
// configuration that can change without dropping listeners or sessions.
//
// The reloadable surface is deliberately narrow and honest: the ACCESS
// policy (client allow-list, rate limit, read-only/write rules). That is
// the part an operator actually changes during an incident — locking a
// write path or cutting off a noisy client — and it is read per datagram,
// so a swap takes effect on the next packet.
//
// Everything bound to a socket or embedded in a crypto session (role,
// tunnel, security.users, engine identity, listeners, notification
// filters, metrics endpoints) needs a restart, and is REPORTED as such
// rather than silently ignored: an operator who edits listen_addr must not
// believe the change took effect.
package proxy

import (
	"fmt"
	"reflect"

	"github.com/GalaxyGorilla/snmp-shield/internal/access"
	"github.com/GalaxyGorilla/snmp-shield/internal/config"
)

// applyReload installs the reloadable part of next into the running
// process and returns human-readable warnings for everything it could not
// apply. An empty slice means the new file was applied completely.
//
// Safety property: a policy that fails to compile keeps the previous one
// installed — a reload typo must never leave the proxy unprotected or
// wide open by accident.
func applyReload(cur, next *config.Config, h *access.Holder) []string {
	var warnings []string

	pol, err := next.AccessPolicy()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"access policy invalid, keeping the running policy: %v", err))
	} else {
		h.Store(pol)
	}

	// restartRequired ignores the access block (applied above) and the
	// role (it selects the code path, not just a value).
	trimmed := *next
	trimmed.Access = cur.Access
	trimmed.Role = cur.Role
	if msgs := restartRequired(*cur, trimmed); len(msgs) > 0 {
		warnings = append(warnings, msgs...)
	}
	return warnings
}

// restartRequired lists the differences a SIGHUP cannot apply.
func restartRequired(cur, next config.Config) []string {
	var msgs []string
	if !reflect.DeepEqual(cur.Tunnel, next.Tunnel) {
		msgs = append(msgs, "tunnel block changed")
	}
	if !reflect.DeepEqual(cur.Security, next.Security) {
		msgs = append(msgs, "security block changed")
	}
	if !reflect.DeepEqual(cur.Manager, next.Manager) {
		msgs = append(msgs, "manager block changed")
	}
	if !reflect.DeepEqual(cur.Agent, next.Agent) {
		msgs = append(msgs, "agent block changed")
	}
	if !reflect.DeepEqual(cur.Gateway, next.Gateway) {
		msgs = append(msgs, "gateway block changed")
	}
	if !reflect.DeepEqual(cur.Notifications, next.Notifications) {
		msgs = append(msgs, "notifications block changed")
	}
	if !reflect.DeepEqual(cur.Metrics, next.Metrics) {
		msgs = append(msgs, "metrics block changed")
	}
	for i := range msgs {
		msgs[i] += " (restart required)"
	}
	return msgs
}

// describePolicy renders a one-line summary of a policy for the reload
// log (never logs communities, keys or passphrases — the policy holds
// none).
func describePolicy(p *access.Policy) string {
	if p == nil {
		return "none (allow everything)"
	}
	mode := "read-write"
	if p.ReadOnly() {
		mode = "read-only"
	}
	return fmt.Sprintf("%s, %d write rules", mode, p.WritePolicyRules())
}
