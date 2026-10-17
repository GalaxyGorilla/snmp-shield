// Package cache implements the engine boots/time store with anti-rollback
// and JSON persistence. The proxy owns one authoritative engine per
// instance; engineBoots increments on every start, engineTime counts
// seconds since start, and inbound boots/time values can never regress.
package cache

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrRollback is returned when an inbound (boots, time) pair would
// regress the stored engine state.
var ErrRollback = errors.New("cache: engine boots/time rollback rejected")

// Engine is one authoritative SNMP engine's state.
type Engine struct {
	EngineID []byte `json:"engine_id"`
	Boots    uint32 `json:"boots"`
	// LastBoots is the highest accepted boots value (anti-rollback floor).
	LastBoots uint32 `json:"last_boots"`
	StartedAt time.Time `json:"started_at"`
}

// Store persists engine state as a JSON file.
type Store struct {
	mu   sync.Mutex
	path string
}

// Open creates/loads the store at path. Missing files are tolerated (the
// store starts empty); corrupt files are an error so rollback protection
// is never silently weakened.
func Open(path string) (*Store, error) {
	if path == "" {
		return &Store{}, nil // memory-only store
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("cache: mkdir: %w", err)
	}
	return &Store{path: path}, nil
}

// LoadEngine loads the persisted engine state, or nil when absent.
func (s *Store) LoadEngine() (*Engine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cache: read: %w", err)
	}
	var e Engine
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("cache: corrupt engine store %s: %w", s.path, err)
	}
	return &e, nil
}

// SaveEngine persists the engine state atomically (write temp + rename).
func (s *Store) SaveEngine(e *Engine) error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("cache: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("cache: write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("cache: rename: %w", err)
	}
	return nil
}

// EngineClock is one running authoritative engine: it owns the engineID,
// boots (persisted, incremented per start) and time (seconds since start).
type EngineClock struct {
	mu        sync.Mutex
	engineID  []byte
	boots     uint32
	startedAt time.Time
	store     *Store
}

// NewEngineClock boots an engine: it loads persisted state, increments
// boots (a new boot of the engine), and saves. An engineID is generated
// deterministically from the persisted one, or randomly when absent
// (unless provided is non-empty, which wins — e.g. from config).
func NewEngineClock(store *Store, provided []byte, log Logger) (*EngineClock, error) {
	prev, err := store.LoadEngine()
	if err != nil {
		return nil, err
	}
	var id []byte
	var boots uint32
	switch {
	case len(provided) > 0:
		id = append([]byte{}, provided...)
		if prev != nil && string(prev.EngineID) == string(provided) {
			boots = prev.Boots + 1
		} else {
			boots = 1
		}
	case prev != nil && len(prev.EngineID) > 0:
		id = append([]byte{}, prev.EngineID...)
		boots = prev.Boots + 1
	default:
		id, err = GenerateEngineID()
		if err != nil {
			return nil, err
		}
		boots = 1
	}
	ec := &EngineClock{engineID: id, boots: boots, startedAt: time.Now(), store: store}
	if err := store.SaveEngine(&Engine{
		EngineID:  append([]byte{}, id...),
		Boots:     boots,
		LastBoots: boots,
		StartedAt: ec.startedAt,
	}); err != nil {
		return nil, err
	}
	if log != nil {
		log.Logf("usm engine up: id=%x boots=%d", id, boots)
	}
	return ec, nil
}

// Logger is the minimal logging interface used by the cache package.
type Logger interface {
	Logf(format string, args ...any)
}

// EngineID returns a copy of the engine ID.
func (ec *EngineClock) EngineID() []byte {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return append([]byte{}, ec.engineID...)
}

// Boots returns the current engine boots.
func (ec *EngineClock) Boots() uint32 {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return ec.boots
}

// Time returns the engine time: seconds since boot.
func (ec *EngineClock) Time() uint32 {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return uint32(time.Since(ec.startedAt).Seconds())
}

// AcceptInbound validates an inbound (boots, time) pair per RFC 3414
// §3.2 step 4: the message is timely when its boots matches this
// engine's boots and its time is within 150 seconds of this engine's
// current engineTime. Anything else (boots mismatch — including
// claimed-future boots — or time outside the window) is rejected.
//
// Anti-rollback: this engine's boots only ever increments across
// restarts (NewEngineClock), so captured messages from before a restart
// always fail the boots check.
func (ec *EngineClock) AcceptInbound(boots, t uint32) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	if boots != ec.boots {
		return ErrRollback
	}
	now := uint32(time.Since(ec.startedAt).Seconds())
	switch {
	case t <= now+150 && (t >= now || now-t <= 150):
		return nil
	default:
		return ErrRollback
	}
}

// GenerateEngineID builds a random 11-byte engine ID per RFC 3414:
// 0x80 | 0x00 ... with random local bytes. Format: first octet 0x80
// (enterprise-dependent high bits), then 10 random bytes.
func GenerateEngineID() ([]byte, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("cache: random engine id: %w", err)
	}
	b[0] = 0x80
	return b, nil
}
