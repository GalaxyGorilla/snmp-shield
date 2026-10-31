package conformance

// A REAL legacy device: the clear v2c leg.
//
// Every other scenario in this package points the proxy at `testkit.NewAgent`,
// which is our own code — an honest little agent (real GETNEXT/GETBULK
// semantics, real exception varbinds), but still written against the same
// `msg` package that produces the requests. So the device-facing leg has never
// been judged by a third party: our v2c request encoding, the PDU we rebuild
// from a v3 or TSM request, and the response parsing on the way back all pass
// through code we also wrote the oracle for.
//
// This fixture closes that: a real net-snmp `snmpd` with a real MIB, a real
// SET target and a real notification engine. Two implementations, as with the
// v3 agent leg: whatever the host ships (Apple's is 5.6.2.1, from 2010) and the
// 5.9.3 in the peer image.
//
// The agent also sends its coldStart notification, so the *device-originated*
// notification path gets a real encoder as well — `informsink` makes it strict,
// because net-snmp retransmits an unconfirmed inform once a second until it
// gives up. A proxy that relays the inform but never confirms it is visible as
// six datagrams instead of one.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GalaxyGorilla/snmp-shield/internal/testkit"
)

// v2cDeviceFixture is a real net-snmp agent acting as the legacy device.
type v2cDeviceFixture interface {
	// Addr is the device's agent address (what the proxy's `--agent` wants).
	Addr() string
	Stop(t *testing.T)
}

// deviceFixture names one implementation and knows how its notifications
// reach a host listener. The mapping lives on the descriptor, not the started
// agent: the notification target has to be in the agent's config *before* it
// starts, and a container reaches the host by a different name than the host
// does.
type deviceFixture struct {
	name   string
	start  func(*testing.T, deviceOptions) v2cDeviceFixture
	target func(bind string) string
}

// loopbackTarget is what a native agent dials: the host's own loopback.
func loopbackTarget(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bind
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// containerTarget is what an agent inside the peer image dials.
func containerTarget(bind string) string {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bind
	}
	return net.JoinHostPort(dockerHost, port)
}

// deviceOptions configures the agent's notification behaviour.
type deviceOptions struct {
	// NotifyAddr, when set, makes the agent send its coldStart notification
	// there at startup.
	NotifyAddr string
	// Inform selects a confirmed notification (`informsink`) instead of a
	// fire-and-forget one (`trap2sink`).
	Inform bool
}

// deviceConf renders an snmpd.conf for a v2c agent.
//
// `rwcommunity` alone, not `rocommunity` + `rwcommunity`. Two directives for
// the same community string produce two VACM entries with the same security
// name, and 5.9 matches the FIRST one: with `rocommunity public` listed first,
// every write is answered `noAccess` (found by the set-lands-in-the-real-mib
// scenario, which the host's Apple 5.6 never reports because that build calls
// both tokens unknown and serves everything on loopback). `rwcommunity`
// grants read and write, which is what a device fixture needs.
func deviceConf(agentAddr string, opts deviceOptions) string {
	body := "agentaddress " + agentAddr + "\n" +
		"rwcommunity " + community + "\n"
	if opts.NotifyAddr != "" {
		if opts.Inform {
			body += "informsink " + opts.NotifyAddr + " " + community + "\n"
		} else {
			body += "trap2sink " + opts.NotifyAddr + " " + community + "\n"
		}
	}
	return body
}

// snmpdDevice is a native net-snmp agent process.
type snmpdDevice struct {
	addr string
	cmd  *exec.Cmd
	log  *lockedBuffer
	done chan struct{}
	once sync.Once
}

func (d *snmpdDevice) Addr() string { return d.addr }

func (d *snmpdDevice) Stop(t *testing.T) {
	t.Helper()
	d.once.Do(func() {
		_ = d.cmd.Process.Kill()
		<-d.done
	})
	if t.Failed() {
		t.Logf("device snmpd output:\n%s", d.log.String())
	}
}

// startV2cSnmpd launches the system snmpd as a clear v2c device.
func startV2cSnmpd(t *testing.T, opts deviceOptions) v2cDeviceFixture {
	t.Helper()
	path := "/usr/sbin/snmpd"
	if p, err := exec.LookPath("snmpd"); err == nil {
		path = p
	}
	if _, err := os.Stat(path); err != nil {
		skipOrFail(t, "snmpd not installed (%s): the clear device leg is unverified on this host", path)
	}

	dir := t.TempDir()
	addr := testkit.FreeUDPPort(t, "127.0.0.1")
	conf := filepath.Join(dir, "snmpd.conf")
	if err := os.WriteFile(conf, []byte(deviceConf(addr, opts)), 0o600); err != nil {
		t.Fatalf("conformance: write device config: %v", err)
	}

	cmd := exec.Command(path, "-f", "-Le", "-C", "-c", conf)
	cmd.Env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+dir)
	lb := &lockedBuffer{}
	cmd.Stdout = lb
	cmd.Stderr = lb
	if err := cmd.Start(); err != nil {
		skipOrFail(t, "snmpd cannot start here: %v", err)
	}
	dev := &snmpdDevice{addr: addr, cmd: cmd, log: lb, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(dev.done)
	}()
	t.Cleanup(func() { dev.Stop(t) })
	return dev
}

// dockerV2cSnmpd is a net-snmp agent inside the peer image.
type dockerV2cSnmpd struct {
	addr string
	name string
	once sync.Once
}

func (d *dockerV2cSnmpd) Addr() string { return d.addr }

func (d *dockerV2cSnmpd) Stop(t *testing.T) {
	t.Helper()
	d.once.Do(func() {
		logs, _ := exec.Command("docker", "logs", d.name).CombinedOutput()
		_ = exec.Command("docker", "rm", "-f", d.name).Run()
		if t.Failed() {
			t.Logf("docker device snmpd (%s) output:\n%s", d.name, logs)
		}
	})
}

// startDockerV2cSnmpd launches the peer image's snmpd 5.9.3 as a clear v2c
// device. The host port comes from docker (never probe-then-publish, see
// CONFORMANCE.md "Docker fixtures").
func startDockerV2cSnmpd(t *testing.T, opts deviceOptions) v2cDeviceFixture {
	t.Helper()
	requireDockerSnmpd(t)

	dir := t.TempDir()
	conf := filepath.Join(dir, "snmpd.conf")
	if err := os.WriteFile(conf, []byte(deviceConf("udp:1161", opts)), 0o644); err != nil {
		t.Fatalf("conformance: write docker device config: %v", err)
	}

	name := fmt.Sprintf("snmp-shield-device-%d-%d", os.Getpid(), time.Now().UnixNano())
	args := []string{
		"run", "-d", "--name", name,
		"-p", "127.0.0.1::1161/udp",
		"-v", dir + ":/peers:ro",
		"-e", "SNMP_PERSISTENT_DIR=/home/peer/.snmp-persist",
		dockerNetSNMPImage,
		"sh", "-c", "mkdir -p /home/peer/.snmp-persist && exec snmpd -f -Le -C -c /peers/snmpd.conf",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		skipOrFail(t, "docker device snmpd cannot start (%s)", firstLine(string(out)))
	}
	pubOut, perr := exec.Command("docker", "port", name, "1161/udp").Output()
	if perr != nil {
		t.Fatalf("conformance: docker port: %v", perr)
	}
	dev := &dockerV2cSnmpd{addr: publishedLoopback(t, strings.TrimSpace(string(pubOut))), name: name}
	t.Cleanup(func() { dev.Stop(t) })
	return dev
}

// deviceFixtures is the pair every real-device scenario runs against: the
// host's own snmpd and the current release in the peer image.
func deviceFixtures() []deviceFixture {
	return []deviceFixture{
		{name: "host-snmpd", start: startV2cSnmpd, target: loopbackTarget},
		{name: "docker-snmpd", start: startDockerV2cSnmpd, target: containerTarget},
	}
}

// waitV2cDevice proves the fixture works before blaming the proxy: a direct
// v2c GET straight at the agent must answer with a real value.
func waitV2cDevice(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		g := newSession(t, addr, "2c", 500*time.Millisecond)
		err := g.Connect()
		if err == nil {
			var pkt *gosnmp.SnmpPacket
			pkt, err = g.Get([]string{sysDescr})
			_ = g.Conn.Close()
			// gosnmp returns err == nil with a PDU error status set, so a
			// transport-only check would call a broken agent ready.
			if err == nil && pkt != nil && pkt.Error != gosnmp.NoError {
				err = fmt.Errorf("agent answered with error status %s", pkt.Error)
			}
		}
		if err == nil {
			return
		}
		last = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("v2c device at %s never answered a direct v2c GET: %v", addr, last)
}
