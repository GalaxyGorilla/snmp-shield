// Package testkit is the shared scaffolding for snmp-shield's tests: fake
// SNMP agents, ephemeral loopback ports, throwaway PKI and an in-memory
// tunnel pipe.
//
// It exists because the same helpers had grown in four or five packages
// (fake agent loops, cert generators, port pickers, frame-sink shims). Each
// copy drifted: one fake agent answered GETNEXT, another did not, one pipe
// dropped frames sent before Subscribe and made the trap path flake. Tests
// that encode protocol expectations should be shared, so the expectations
// are written once and every suite exercises the same device behaviour.
//
// Conventions:
//   - Bind ephemeral ports ("127.0.0.1:0") and read LocalAddr(); fixed
//     loopback ports collide under `go test -race ./...` where packages run
//     in parallel. FreeUDPPort is for the rare case where a config needs an
//     address before a listener exists.
//   - Everything takes testing.TB and registers cleanup; a test never
//     closes what it did not open.
//   - The fake agent is a *device*, not a proxy: it answers v1/v2c only,
//     with honest GETNEXT/GETBULK semantics and real exceptions, because a
//     too-forgiving device hides proxy bugs.
//
// This package is imported only by tests; nothing in the binary links it.
package testkit
