// readloop_done_test.go — the invariant the whole per-session lifecycle rests
// on: when the read loop ends, Done() fires.
//
// Done() is what cancels a per-session translator (usm/tsm/passthrough key
// their goroutines on it). The read loop is the only reader and is started
// once, so its exit means "no frame will ever arrive again" — the session is
// over for its consumers. That has to hold on every exit path, including the
// ones that do not drop the connection themselves.
//
// It did not. A server session answering a PING whose PONG write fails calls
// dropConn from inside the loop (TunnelDown fires correctly), then `continue`s,
// finds no connection, and returned without closeDone: Done never fired and
// the translator for that client leaked for the rest of the process's life —
// the same class the soak found for reconnects, on a path no functional test
// reached. Found by running the panic test under -coverpkg (which slows
// everything enough to hit the PING branch); pinned here deterministically
// with a fake connection, so it does not depend on timing.
package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeConn feeds the read loop one frame and then blocks, and fails every
// write. That is the shape of a client that vanished mid-exchange.
type fakeConn struct {
	r      io.Reader
	closed chan struct{}
	once   sync.Once
}

func newFakeConn(feed []byte) *fakeConn {
	return &fakeConn{r: bytes.NewReader(feed), closed: make(chan struct{})}
}

func (c *fakeConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == io.EOF {
		// A real peer that vanished mid-exchange leaves the read blocking
		// until the deadline; blocking is also what keeps the loop from
		// exiting for the wrong reason here.
		<-c.closed
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *fakeConn) Write([]byte) (int, error) { return 0, errors.New("peer gone") }

func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *fakeConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// TestReadLoopExitFiresDoneAfterFailedPong drives the exact path: a PING
// arrives, answering it fails, the loop finds no connection and returns.
// Done() must fire.
func TestReadLoopExitFiresDoneAfterFailedPong(t *testing.T) {
	ping := &Frame{Type: TypePING, CorrID: 7}
	conn := newFakeConn(ping.Marshal())

	sess := NewServerSession(conn, 65536, 1200, zap.NewNop())
	defer func() { _ = sess.Close() }()

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done() never fired after the read loop exited on a failed PONG: the per-session translator would leak")
	}

	// A subscriber channel must be closed too: the loops that range over it
	// (`for f := range ch`) park forever otherwise.
	ch, cancel := sess.Subscribe(TypeREQ)
	defer cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("subscriber channel delivered a frame after the session ended")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber channel was not closed when the session ended")
	}
}
