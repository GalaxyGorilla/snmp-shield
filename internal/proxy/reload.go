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
	warnings, _, _ := applyReloadDetailed(cur, next, h)
	return warnings
}

// applyReloadDetailed is applyReload plus the status view: whether the
// access policy was installed and which differences still need a restart.
func applyReloadDetailed(cur, next *config.Config, h *access.Holder) (warnings, restart []string, applied bool) {
	applied = true

	pol, err := next.AccessPolicy()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"access policy invalid, keeping the running policy: %v", err))
		applied = false
	} else if h != nil {
		h.Store(pol)
	}

	// restartRequired ignores the access block (applied above) and the
	// role (it selects the code path, not just a value).
	trimmed := *next
	trimmed.Access = cur.Access
	trimmed.Role = cur.Role
	restart = restartRequired(*cur, trimmed)
	warnings = append(warnings, restart...)
	return warnings, restart, applied
}

// agentReloadResult is the per-entry status of one agents: reload.
type agentReloadResult struct {
	policyApplied   bool
	restartRequired []string
}

// applyReloadAgents installs the per-agent access policies for the
// multi-agent gateway shape and reports everything that needs a restart.
func applyReloadAgents(cur, next *config.Config, holders map[string]*access.Holder) []string {
	warnings, _, _ := applyReloadAgentsDetailed(cur, next, holders)
	return warnings
}

// applyReloadAgentsDetailed is applyReloadAgents plus the per-entry status
// view used by /status.
func applyReloadAgentsDetailed(cur, next *config.Config, holders map[string]*access.Holder) (warnings, restart []string, perAgent map[string]agentReloadResult) {
	perAgent = make(map[string]agentReloadResult)
	if !next.HasAgents() {
		msg := "agents list removed; restart required"
		warnings = append(warnings, msg)
		restart = append(restart, msg)
		for _, a := range cur.Agents {
			perAgent[a.EffectiveName()] = agentReloadResult{
				policyApplied:   false,
				restartRequired: []string{"removed"},
			}
		}
		return warnings, restart, perAgent
	}
	curByName := make(map[string]config.AgentEntry, len(cur.Agents))
	for _, a := range cur.Agents {
		curByName[a.EffectiveName()] = a
	}
	nextByName := make(map[string]config.AgentEntry, len(next.Agents))
	for _, a := range next.Agents {
		nextByName[a.EffectiveName()] = a
	}
	for name, a := range nextByName {
		old, existed := curByName[name]
		res := agentReloadResult{policyApplied: true}
		if !existed {
			msg := fmt.Sprintf("agent %s added; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.policyApplied = false
			res.restartRequired = append(res.restartRequired, "added")
			perAgent[name] = res
			continue
		}
		pol, err := next.EffectiveAccess(a).Policy()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"agent %s access policy invalid, keeping the running policy: %v", name, err))
			res.policyApplied = false
		} else if h := holders[name]; h != nil {
			h.Store(pol)
		} else {
			msg := fmt.Sprintf("agent %s has no running access holder; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.policyApplied = false
			res.restartRequired = append(res.restartRequired, "no access holder")
		}
		if old.ListenAddr != a.ListenAddr || old.AgentAddr != a.AgentAddr || old.AgentCommunity != a.AgentCommunity {
			msg := fmt.Sprintf("agent %s listener/agent changed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.restartRequired = append(res.restartRequired, "listener/agent changed")
		}
		if !reflect.DeepEqual(old.Security, a.Security) {
			msg := fmt.Sprintf("agent %s security changed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.restartRequired = append(res.restartRequired, "security changed")
		}
		if !reflect.DeepEqual(old.TLS, a.TLS) {
			msg := fmt.Sprintf("agent %s tls changed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.restartRequired = append(res.restartRequired, "tls changed")
		}
		if !reflect.DeepEqual(old.Notifications, a.Notifications) {
			msg := fmt.Sprintf("agent %s notifications changed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.restartRequired = append(res.restartRequired, "notifications changed")
		}
		if old.TrapListenAddr != a.TrapListenAddr || old.TrapSinkAddr != a.TrapSinkAddr ||
			old.TrapSinkCommunity != a.TrapSinkCommunity {
			msg := fmt.Sprintf("agent %s trap legs changed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			res.restartRequired = append(res.restartRequired, "trap legs changed")
		}
		perAgent[name] = res
	}
	for name := range curByName {
		if _, ok := nextByName[name]; !ok {
			msg := fmt.Sprintf("agent %s removed; restart required", name)
			warnings = append(warnings, msg)
			restart = append(restart, msg)
			perAgent[name] = agentReloadResult{
				policyApplied:   false,
				restartRequired: []string{"removed"},
			}
		}
	}
	var top []string
	if !reflect.DeepEqual(cur.Tunnel, next.Tunnel) {
		top = append(top, "tunnel block changed (restart required)")
	}
	if !reflect.DeepEqual(cur.Security, next.Security) {
		top = append(top, "security block changed (restart required)")
	}
	if !reflect.DeepEqual(cur.Gateway, next.Gateway) {
		top = append(top, "gateway block changed (restart required)")
	}
	if !reflect.DeepEqual(cur.Notifications, next.Notifications) {
		top = append(top, "notifications block changed (restart required)")
	}
	if !reflect.DeepEqual(cur.Metrics, next.Metrics) {
		top = append(top, "metrics block changed (restart required)")
	}
	warnings = append(warnings, top...)
	restart = append(restart, top...)
	// A process-wide change affects every entry that keeps running.
	if len(top) > 0 {
		for name, res := range perAgent {
			if _, ok := nextByName[name]; !ok {
				continue
			}
			res.restartRequired = append(res.restartRequired, top...)
			perAgent[name] = res
		}
	}
	return warnings, restart, perAgent
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
