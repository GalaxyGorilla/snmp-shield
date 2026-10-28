package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// execPeer runs one of the adapters in test/peers as a subprocess.
//
// The adapters exist because a vendor stack in its own runtime is the only
// way to keep it honestly independent: reimplementing pysnmp's quirks in Go
// would put us right back where the Go-only tests are.
type execPeer struct {
	name  string
	stack string
	// cmd is the full command prefix, ending with the adapter script.
	cmd []string
	// requires lists executables that must exist (checked with LookPath).
	requires []string
	// requireModule is a Python import or Node module that must be present.
	requireModule string
	// moduleRuntime selects how requireModule is checked: "python" or "node".
	moduleRuntime string

	once     sync.Once
	unavail  string
	probeSum string
}

func newExecPeer(name, stack, runtime string, scripts []string, requires string) *execPeer {
	p := &execPeer{name: name, stack: stack}
	dir := peersDir()
	if runtime != "" {
		// A runtime containing a slash is a path inside test/peers
		// (the venv), not a PATH lookup: resolve it now, because the
		// adapter runs with the package directory as working directory.
		if strings.Contains(runtime, "/") && !filepath.IsAbs(runtime) {
			runtime = filepath.Join(dir, runtime)
		}
		p.cmd = append(p.cmd, runtime)
	}
	for _, s := range scripts {
		p.cmd = append(p.cmd, filepath.Join(dir, s))
	}
	if requires != "" {
		p.requires = append(p.requires, requires)
	}
	switch name {
	case "pysnmp":
		p.requireModule = "pysnmp, cryptography"
		p.moduleRuntime = "python"
	case "node":
		p.requireModule = filepath.Join(dir, "node_modules", "net-snmp")
		p.moduleRuntime = "node"
	}
	return p
}

func (p *execPeer) Name() string  { return p.name }
func (p *execPeer) Stack() string { return p.stack }

func (p *execPeer) Unavailable() string {
	p.once.Do(func() {
		for _, exe := range p.requires {
			if _, err := exec.LookPath(exe); err != nil {
				p.unavail = fmt.Sprintf("%s not found in PATH", exe)
				return
			}
		}
		for _, part := range p.cmd {
			if filepath.IsAbs(part) {
				if _, err := os.Stat(part); err != nil {
					p.unavail = fmt.Sprintf("%s missing (run scripts/peers-setup.sh)", part)
					return
				}
			}
		}
		switch p.moduleRuntime {
		case "python":
			out, err := exec.Command(p.cmd[0], "-c", "import "+p.requireModule).CombinedOutput()
			if err != nil {
				p.unavail = fmt.Sprintf("python module missing (%s) — run scripts/peers-setup.sh: %s",
					p.requireModule, firstLine(string(out)))
				return
			}
		case "node":
			if _, err := os.Stat(p.requireModule); err != nil {
				p.unavail = "node_modules/net-snmp missing — run scripts/peers-setup.sh"
				return
			}
		}
		p.probeSum = p.stack
	})
	return p.unavail
}

func (p *execPeer) Run(ctx context.Context, req Request) (Result, error) {
	cmd := exec.CommandContext(ctx, p.cmd[0], append(p.cmd[1:], p.args(req)...)...)
	cmd.Dir = peersDir()
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			return Result{}, fmt.Errorf("%s: %w: %s", p.name, err, firstLine(string(exitErr.Stderr)))
		}
		return Result{}, fmt.Errorf("%s: %w", p.name, err)
	}
	var res Result
	if jerr := json.Unmarshal(lastJSONLine(out), &res); jerr != nil {
		return Result{}, fmt.Errorf("%s: unparseable adapter output (%v): %s", p.name, jerr, firstLine(string(out)))
	}
	return res, nil
}

func (p *execPeer) args(req Request) []string {
	args := []string{string(req.Verb)}
	add := func(flag, value string) {
		if value != "" {
			args = append(args, flag, value)
		}
	}
	add("--version", req.Version)
	add("--level", req.Level)
	add("--community", req.Community)
	add("--user", req.User)
	add("--auth", req.Auth)
	add("--priv", req.Priv)
	add("--auth-proto", req.AuthProto)
	add("--priv-proto", req.PrivProto)
	add("--target", req.Target)
	if req.Timeout > 0 {
		args = append(args, "--timeout", strconv.FormatFloat(req.Timeout, 'f', -1, 64))
	}
	if req.Retries > 0 {
		args = append(args, "--retries", strconv.Itoa(req.Retries))
	}
	if req.MaxRepetitions > 0 {
		args = append(args, "--max-repetitions", strconv.Itoa(req.MaxRepetitions))
	}
	for _, oid := range req.OIDs {
		args = append(args, "--oid", oid)
	}
	for _, vb := range req.Varbinds {
		args = append(args, "--varbind", vb)
	}
	if req.Enterprise != "" {
		args = append(args, "--enterprise", req.Enterprise)
	}
	if req.AgentAddr != "" {
		args = append(args, "--agent-addr", req.AgentAddr)
	}
	if req.Specific != 0 {
		args = append(args, "--specific", strconv.Itoa(req.Specific))
	}
	if req.Generic != 0 {
		args = append(args, "--generic", strconv.Itoa(req.Generic))
	}
	return args
}

// peersDir is the adapter directory, independent of the test's working
// directory (which is this package's directory).
func peersDir() string {
	return filepath.Join(repoRoot(), "test", "peers")
}

// repoRoot walks up from the working directory looking for go.mod.
func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// lastJSONLine makes the adapter contract tolerant of vendor noise on
// stdout (net-snmp prints MIB warnings); the LAST line must be the JSON.
func lastJSONLine(out []byte) []byte {
	lines := splitLines(out)
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) > 0 && lines[i][0] == '{' {
			return lines[i]
		}
	}
	return out
}

func splitLines(out []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range out {
		if b == '\n' {
			lines = append(lines, out[start:i])
			start = i + 1
		}
	}
	if start < len(out) {
		lines = append(lines, out[start:])
	}
	return lines
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

func asExitError(err error, out **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*out = ee
		return true
	}
	return false
}
