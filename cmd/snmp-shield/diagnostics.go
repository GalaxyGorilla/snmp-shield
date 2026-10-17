package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/GalaxyGorilla/snmp-shield/internal/config"
	"github.com/GalaxyGorilla/snmp-shield/internal/msg"
	"github.com/GalaxyGorilla/snmp-shield/internal/tunnel"
	"github.com/GalaxyGorilla/snmp-shield/internal/usm"
	"github.com/spf13/pflag"
)

// check is one selftest/validate result line.
type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// report is the JSON document printed by validate --json and
// selftest --json (for tooling / web UIs).
type report struct {
	OK           bool    `json:"ok"`
	Role         string  `json:"role,omitempty"`
	SecurityMode string  `json:"security_mode,omitempty"`
	TunnelMode   string  `json:"tunnel_mode,omitempty"`
	Error        string  `json:"error,omitempty"`
	Checks       []check `json:"checks,omitempty"`
}

// roleArg parses the --role flag (manager|agent|gateway).
func roleArg(s string) (config.Role, error) {
	switch s {
	case "manager":
		return config.RoleManager, nil
	case "agent":
		return config.RoleAgent, nil
	case "gateway":
		return config.RoleGateway, nil
	case "":
		return "", fmt.Errorf("--role is required (manager, agent or gateway)")
	default:
		return "", fmt.Errorf("unknown role %q (use manager, agent or gateway)", s)
	}
}

// loadChecked builds a validated Config the same way the role
// subcommands do: --config YAML or direct flags.
func loadChecked(role config.Role, c cliFlags) (*config.Config, error) {
	if *c.configPath != "" {
		return config.Load(*c.configPath, role)
	}
	return flagsConfig(role, c.opts())
}

// runValidate loads and validates a configuration without running the
// proxy. Exit 0 = valid, 1 = invalid. This is the pre-apply hook for
// tooling: it also pre-flights certificate material and the engine
// store path, which Validate only checks for non-emptiness.
func runValidate(args []string) int {
	fs := pflag.NewFlagSet("validate", pflag.ContinueOnError)
	c := register(fs)
	roleStr := fs.String("role", "", "role to validate: manager, agent or gateway (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rep report
	rep.Role = *roleStr
	role, err := roleArg(*roleStr)
	if err != nil {
		rep.Error = err.Error()
		return finishValidate(rep, *c.jsonOut)
	}

	cfg, err := loadChecked(role, c)
	if err != nil {
		rep.Error = err.Error()
		return finishValidate(rep, *c.jsonOut)
	}
	rep.SecurityMode = cfg.Security.Mode
	rep.TunnelMode = cfg.Tunnel.Mode

	// Pre-flight local resources the YAML validation cannot check.
	rep.Checks = preflight(cfg)
	for _, ch := range rep.Checks {
		if !ch.OK {
			rep.Error = ch.Name + ": " + ch.Detail
			return finishValidate(rep, *c.jsonOut)
		}
	}
	return finishValidate(rep, *c.jsonOut)
}

func finishValidate(rep report, jsonOut bool) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
		// exit code mirrors ok in both modes (matches selftest and the
		// "Exit 0/1" contract); the JSON report on stdout carries the
		// details for tooling either way.
		if !rep.OK {
			return 1
		}
		return 0
	}
	if !rep.OK {
		fmt.Fprintf(os.Stderr, "invalid: %s\n", rep.Error)
		return 1
	}
	fmt.Printf("ok: role=%s security=%s", rep.Role, rep.SecurityMode)
	if rep.TunnelMode != "" {
		fmt.Printf(" tunnel=%s", rep.TunnelMode)
	}
	fmt.Println()
	return 0
}

// preflight checks local resources referenced by the config: tunnel
// certificate material and the engine store path. Returns one check per
// resource (only the ones the config references).
func preflight(cfg *config.Config) []check {
	var out []check
	t := cfg.Tunnel
	if t.CertFile != "" || t.KeyFile != "" {
		out = append(out, checkKeyPair(t.CertFile, t.KeyFile))
	}
	if t.CAFile != "" {
		out = append(out, checkCA(t.CAFile))
	}
	if cfg.Security.EngineStore != "" {
		out = append(out, checkEngineStore(cfg.Security.EngineStore))
	}
	return out
}

func checkKeyPair(certFile, keyFile string) check {
	if certFile == "" || keyFile == "" {
		return check{Name: "tunnel keypair", OK: false, Detail: "cert_file and key_file must both be set"}
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return check{Name: "tunnel keypair", OK: false, Detail: fmt.Sprintf("%s + %s: %v", certFile, keyFile, err)}
	}
	return check{Name: "tunnel keypair", OK: true, Detail: certFile}
}

func checkCA(caFile string) check {
	data, err := os.ReadFile(caFile)
	if err != nil {
		return check{Name: "tunnel CA", OK: false, Detail: err.Error()}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return check{Name: "tunnel CA", OK: false, Detail: caFile + ": no usable certificates"}
	}
	return check{Name: "tunnel CA", OK: true, Detail: caFile}
}

func checkEngineStore(path string) check {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return check{Name: "engine store", OK: false, Detail: err.Error()}
	}
	_ = f.Close()
	return check{Name: "engine store", OK: true, Detail: path}
}

// runSelftest validates the configuration and then probes the
// environment the configured instance depends on: local files, the
// real agent/manager behind the proxy, and (manager role) the tunnel
// handshake. Designed for appliance health checks and web-UI
// "test connection" buttons. Exit 0 = all checks passed.
func runSelftest(args []string) int {
	fs := pflag.NewFlagSet("selftest", pflag.ContinueOnError)
	c := register(fs)
	roleStr := fs.String("role", "", "role to test: manager, agent or gateway (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var rep report
	rep.Role = *roleStr
	role, err := roleArg(*roleStr)
	if err != nil {
		rep.Error = err.Error()
		return finishSelftest(rep, *c.jsonOut)
	}

	cfg, err := loadChecked(role, c)
	if err != nil {
		rep.Error = "config: " + err.Error()
		return finishSelftest(rep, *c.jsonOut)
	}
	rep.SecurityMode = cfg.Security.Mode
	rep.TunnelMode = cfg.Tunnel.Mode
	rep.Checks = append(rep.Checks, check{Name: "config", OK: true,
		Detail: fmt.Sprintf("role=%s security=%s", role, cfg.Security.Mode)})
	rep.Checks = append(rep.Checks, preflight(cfg)...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if *c.selftestProbe {
		switch role {
		case config.RoleManager:
			rep.Checks = append(rep.Checks, probeTunnel(ctx, cfg)...)
		case config.RoleAgent:
			rep.Checks = append(rep.Checks, probeAgent(ctx, cfg.Agent.AgentAddr, agentCommunity(cfg)))
		case config.RoleGateway:
			// tsm-gateway front-leg material is checked by preflight;
			// the leg that must work is toward the legacy agent.
			if cfg.Security.Mode == "tsm-gateway" {
				rep.Checks = append(rep.Checks, probeCertExpiry(cfg.Tunnel.CertFile))
			}
			// notification-only usm-gateway (no request path) has no
			// agent to probe. usm-manager-gateway fronts a v3 agent:
			// the clear-v2c probe below cannot authenticate there, so
			// the agent is probed with a v3 USM authPriv GET instead
			// (the gateway's own configured credentials).
			if cfg.Security.Mode == "usm-manager-gateway" {
				rep.Checks = append(rep.Checks, probeAgentV3(ctx, cfg))
			} else if cfg.Gateway.AgentAddr != "" {
				rep.Checks = append(rep.Checks, probeAgent(ctx, cfg.Gateway.AgentAddr, gatewayCommunity(cfg)))
			}
		}
	}

	for _, ch := range rep.Checks {
		if !ch.OK {
			rep.Error = ch.Name + ": " + ch.Detail
			break
		}
	}
	return finishSelftest(rep, *c.jsonOut)
}

func finishSelftest(rep report, jsonOut bool) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
	} else {
		for _, ch := range rep.Checks {
			status := "ok"
			if !ch.OK {
				status = "FAIL"
			}
			if ch.Detail != "" {
				fmt.Printf("  %-16s %-4s %s\n", ch.Name, status, ch.Detail)
			} else {
				fmt.Printf("  %-16s %-4s\n", ch.Name, status)
			}
		}
		if rep.OK {
			fmt.Println("selftest passed")
		}
	}
	if !rep.OK {
		fmt.Fprintf(os.Stderr, "selftest FAILED: %s\n", rep.Error)
		return 1
	}
	return 0
}

// agentCommunity picks the v1/v2c community used toward the real agent.
func agentCommunity(cfg *config.Config) string {
	if len(cfg.Security.Users) > 0 && cfg.Security.Users[0].Community != "" {
		return cfg.Security.Users[0].Community
	}
	if cfg.Agent.AgentCommunity != "" {
		return cfg.Agent.AgentCommunity
	}
	return "public"
}

// gatewayCommunity picks the v1/v2c community used toward the legacy
// agent behind a gateway.
func gatewayCommunity(cfg *config.Config) string {
	if cfg.Gateway.AgentCommunity != "" {
		return cfg.Gateway.AgentCommunity
	}
	return "public"
}

// probeTunnel dials every configured tunnel endpoint (manager role) and
// reports the (D)TLS handshake result per endpoint — a dead peer is the
// most common appliance failure.
func probeTunnel(ctx context.Context, cfg *config.Config) []check {
	psk, err := cfg.PSKBytes()
	if err != nil {
		return []check{{Name: "tunnel", OK: false, Detail: err.Error()}}
	}
	addrs := cfg.DialEndpoints()
	if len(addrs) == 0 {
		return []check{{Name: "tunnel", OK: false, Detail: "no tunnel endpoints configured"}}
	}
	var checks []check
	for _, addr := range addrs {
		d := &tunnel.Dialer{
			Mode:            cfg.Tunnel.Mode,
			RemoteAddr:      addr,
			PSK:             psk,
			PSKIdentity:     []byte(cfg.Tunnel.PSKIdentity),
			PskCiphersuites: cfg.Tunnel.PskCiphersuites,
			CAFile:          cfg.Tunnel.CAFile,
			CertFile:        cfg.Tunnel.CertFile,
			KeyFile:         cfg.Tunnel.KeyFile,
			ServerName:      cfg.Tunnel.ServerName,
			Insecure:        cfg.Tunnel.InsecureSkipVerify,
			Timeout:         5 * time.Second,
		}
		pctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		conn, err := d.Dial(pctx, addr)
		cancel()
		if err != nil {
			checks = append(checks, check{Name: "tunnel " + addr, OK: false, Detail: err.Error()})
			continue
		}
		_ = conn.Close()
		checks = append(checks, check{Name: "tunnel " + addr, OK: true, Detail: "handshake ok"})
	}
	return checks
}

// probeAgent sends one SNMPv2c GET (sysDescr.0) to the real agent behind
// the proxy and waits for a GetResponse — proves the legacy device is
// reachable and speaks the expected community. Two attempts (some
// devices drop the first query after ARP resolution).
func probeAgent(ctx context.Context, addr, community string) check {
	name := "agent " + addr
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	pdu := msg.BuildPDU(msg.PDUGetRequest, 1, 0, 0, sysDescrVarbinds())
	dg, err := msg.BuildV1V2c(msg.Version2c, []byte(community), pdu)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	defer conn.Close()

	var lastErr string
	for attempt := 0; attempt < 2; attempt++ {
		deadline := time.Now().Add(2 * time.Second)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetDeadline(deadline)
		if _, err := conn.Write(dg); err != nil {
			return check{Name: name, OK: false, Detail: err.Error()}
		}
		buf := make([]byte, 65536)
		n, rerr := conn.Read(buf)
		if rerr == nil {
			version, _, pduTLV, perr := msg.SplitV1V2c(buf[:n])
			if perr != nil {
				return check{Name: name, OK: false, Detail: "response not SNMP v1/v2c: " + perr.Error()}
			}
			ptype, _, rerr := msg.ParsePDU(pduTLV)
			if rerr != nil {
				return check{Name: name, OK: false, Detail: "response PDU unparsable: " + rerr.Error()}
			}
			if ptype != msg.PDUGetResponse {
				return check{Name: name, OK: false, Detail: fmt.Sprintf("unexpected PDU type 0x%02x in response", ptype)}
			}
			ver := "v1"
			if version == msg.Version2c {
				ver = "v2c"
			}
			return check{Name: name, OK: true, Detail: fmt.Sprintf("GET sysDescr.0 ok (community %q, SNMP %s)", community, ver)}
		}
		lastErr = rerr.Error()
	}
	return check{Name: name, OK: false, Detail: "no response: " + lastErr}
}

// sysDescrVarbinds builds the raw varbind-list content for a single GET
// varbind: sysDescr.0 = NULL (a varbind TLV wrapped in the varbind-list
// SEQUENCE, as BuildPDU expects).
func sysDescrVarbinds() []byte {
	oid, err := msg.EncodeOID("1.3.6.1.2.1.1.1.0")
	if err != nil {
		return nil
	}
	varbind := msg.AppendTLV(nil, 0x30, msg.AppendTLV(nil, 0x06, oid))
	return msg.AppendTLV(nil, 0x30, varbind)
}

// probeAgentV3 probes the v3 agent behind an usm-manager-gateway: the
// clear-v2c probeAgent cannot authenticate there, so this performs a
// full RFC 3414 discovery (Reportable NoAuthNoPriv empty GET) and then
// one authPriv GET for sysDescr.0 with the gateway's configured
// credentials, verifying the response digest and decrypting it. This is
// the exact flow the gateway itself drives per request.
func probeAgentV3(ctx context.Context, cfg *config.Config) check {
	name := "agent(v3) " + cfg.Gateway.AgentAddr
	gw := cfg.Gateway
	sec := cfg.Security
	if len(sec.Users) == 0 {
		return check{Name: name, OK: false, Detail: "no security.users configured"}
	}
	u := sec.Users[0]
	authP, err := usm.ParseAuthProtocol(u.AuthProtocol)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	privP, err := usm.ParsePrivProtocol(u.PrivProtocol)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	if authP == usm.AuthNone || privP == usm.PrivNone {
		return check{Name: name, OK: false, Detail: "usm-manager-gateway needs an authPriv user"}
	}

	// RFC 3414 discovery: Reportable NoAuthNoPriv empty GET.
	pdu := msg.BuildPDU(msg.PDUGetRequest, 1, 0, 0, []byte{0})
	scoped := msg.BuildScoped(nil, []byte{}, pdu)
	out, err := msg.BuildV3(msg.V3Header{
		MsgID:      100,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   msg.MsgFlagReportable,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{}, scoped, nil)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	resp, err := v3Exchange(ctx, gw.AgentAddr, out, 5*time.Second)
	if err != nil {
		return check{Name: name, OK: false, Detail: "discovery: " + err.Error()}
	}
	m, err := msg.ParseV3(resp)
	if err != nil || len(m.USM.EngineID) == 0 {
		return check{Name: name, OK: false, Detail: "discovery: no engineID in agent report"}
	}

	// authPriv GET sysDescr.0 with the discovered engine state.
	profs, err := usm.NewProfilesFromSecurity(sec, m.USM.EngineID)
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	uC, ok := profs.Lookup(sec.Users[0].Name)
	if !ok {
		return check{Name: name, OK: false, Detail: "user not compiled: " + sec.Users[0].Name}
	}
	getPdu := msg.BuildPDU(msg.PDUGetRequest, 2, 0, 0, sysDescrVarbinds())
	getScoped := msg.BuildScoped(m.USM.EngineID, []byte{}, getPdu)
	flags := byte(msg.MsgFlagAuth | msg.MsgFlagPriv | msg.MsgFlagReportable)
	privParams := make([]byte, 8) // zero salt: one-shot probe
	authParams := make([]byte, uC.Profile().AuthProtocol.MacLength())
	get, err := msg.BuildV3(msg.V3Header{
		MsgID:      101,
		MsgMaxSize: msg.DefaultMsgMaxSize,
		MsgFlags:   flags,
		SecModel:   msg.SecurityModelUSM,
	}, msg.USMParams{
		EngineID:   m.USM.EngineID,
		Boots:      m.USM.Boots,
		Time:       m.USM.Time,
		UserName:   sec.Users[0].Name,
		AuthParams: authParams,
		PrivParams: privParams,
	}, getScoped, func(plain []byte) ([]byte, error) {
		return usm.EncryptScoped(uC.Profile().PrivProtocol, uC.PrivKey(), m.USM.Boots, m.USM.Time, privParams, plain)
	})
	if err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}
	if err := usm.SignV3(get, uC.Profile().AuthProtocol, uC.AuthKey()); err != nil {
		return check{Name: name, OK: false, Detail: err.Error()}
	}

	resp, err = v3Exchange(ctx, gw.AgentAddr, get, 5*time.Second)
	if err != nil {
		return check{Name: name, OK: false, Detail: "authPriv GET: " + err.Error()}
	}
	m2, err := msg.ParseV3(resp)
	if err != nil {
		return check{Name: name, OK: false, Detail: "response unparseable: " + err.Error()}
	}
	if _, _, err := usm.UnwrapV3(profs, m2, resp); err != nil {
		return check{Name: name, OK: false, Detail: "response rejected: " + err.Error()}
	}
	return check{Name: name, OK: true, Detail: fmt.Sprintf("discovery + authPriv GET ok (user %q, engine %x)", sec.Users[0].Name, m.USM.EngineID)}
}

// v3Exchange sends one datagram to addr and waits for one v3 response on
// a fresh ephemeral socket.
func v3Exchange(ctx context.Context, addr string, dg []byte, wait time.Duration) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(dg, raddr); err != nil {
		return nil, err
	}
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		out := append([]byte(nil), buf[:n]...)
		// skip stray datagrams: we only accept v3 back
		if info, perr := msg.Peek(out); perr == nil && info.Version == msg.Version3 {
			return out, nil
		}
	}
}

// probeCertExpiry warns when the tsm-gateway front certificate is
// expired or expires within 30 days (a common appliance failure mode).
func probeCertExpiry(certFile string) check {
	if certFile == "" {
		return check{Name: "front cert", OK: false, Detail: "no cert configured"}
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return check{Name: "front cert", OK: false, Detail: err.Error()}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return check{Name: "front cert", OK: false, Detail: certFile + ": no PEM block"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return check{Name: "front cert", OK: false, Detail: err.Error()}
	}
	switch d := time.Until(cert.NotAfter); {
	case d < 0:
		return check{Name: "front cert", OK: false, Detail: fmt.Sprintf("%s: EXPIRED %s ago", certFile, -d.Round(24*time.Hour))}
	case d < 30*24*time.Hour:
		return check{Name: "front cert", OK: true, Detail: fmt.Sprintf("%s: expires in %s (renew soon)", certFile, d.Round(24*time.Hour))}
	default:
		return check{Name: "front cert", OK: true, Detail: fmt.Sprintf("%s: valid until %s", certFile, cert.NotAfter.Format("2006-01-02"))}
	}
}
