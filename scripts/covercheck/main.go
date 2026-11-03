// Command covercheck enforces per-package statement-coverage floors from a
// `go test -coverprofile` file.
//
// A single overall percentage hides the package that regressed: adding a
// large, lightly-tested file can leave the total flat while the security
// boundary drops ten points. This tool makes each floor explicit, keeps the
// policy in a reviewable text file, and fails the build on the first package
// below its floor.
//
// Usage:
//
//	go run ./scripts/covercheck dist/cover.out coverage.floors
//
// Floors file format (one package per line):
//
//	# package          minimum percent
//	ALL                69
//	internal/proxy     75
//	internal/testkit   skip
//
// A package name matches by exact import path or by path suffix, so
// `internal/proxy` is enough. `skip` documents a package that is deliberately
// excluded (test-only helpers, command fixtures). Every non-comment entry
// must match at least one package in the profile; a typo fails the run.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

type stat struct {
	covered int
	total   int
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: covercheck <coverprofile> <floors-file>")
		os.Exit(2)
	}
	stats, err := parseProfile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "covercheck: %v\n", err)
		os.Exit(2)
	}
	floors, err := parseFloors(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "covercheck: %v\n", err)
		os.Exit(2)
	}

	matched := make(map[string]bool)
	failures := 0
	totalCovered, totalStatements := 0, 0

	names := make([]string, 0, len(stats))
	for name := range stats {
		names = append(names, name)
	}
	sort.Strings(names)

	fmt.Printf("%-52s %7s %7s %6s\n", "package", "cover", "floor", "status")
	for _, name := range names {
		s := stats[name]
		pct := percent(s.covered, s.total)

		floor, ok, skip := lookup(name, floors, matched)
		if !skip {
			// The overall figure is the production surface: test-only
			// helpers and tooling are excluded rather than counted as
			// uncovered code, which would make the total depend on how
			// much test scaffolding the repo happens to contain.
			totalCovered += s.covered
			totalStatements += s.total
		}
		status := "ok"
		switch {
		case skip:
			status = "skip"
		case !ok:
			status = "-"
		case pct < floor:
			status = "FAIL"
			failures++
		}
		floorText := "-"
		if ok && !skip {
			floorText = fmt.Sprintf("%.1f", floor)
		} else if skip {
			floorText = "skip"
		}
		fmt.Printf("%-52s %6.1f%% %7s %6s\n", short(name), pct, floorText, status)
	}

	// Every named floor must have matched something. This catches a rename
	// or a typo that would otherwise silently stop enforcing a package.
	for _, name := range floorNames(floors) {
		if name == "ALL" {
			continue
		}
		if !matched[name] {
			fmt.Fprintf(os.Stderr, "covercheck: floor %q matches no package in the profile\n", name)
			failures++
		}
	}

	overall := percent(totalCovered, totalStatements)
	if floor, ok, skip := lookup("ALL", floors, matched); ok && !skip && overall < floor {
		fmt.Fprintf(os.Stderr, "covercheck: overall %.1f%% below floor %.1f%%\n", overall, floor)
		failures++
	}

	fmt.Printf("\noverall: %.1f%% of %d statements\n", overall, totalStatements)
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "covercheck: %d coverage violation(s)\n", failures)
		os.Exit(1)
	}
}

func percent(covered, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(covered) / float64(total)
}

func short(importPath string) string {
	if i := strings.Index(importPath, "/internal/"); i >= 0 {
		return importPath[i+1:]
	}
	if i := strings.LastIndex(importPath, "/"); i >= 0 {
		return importPath[i+1:]
	}
	return importPath
}

// parseProfile aggregates the statement counts in a Go cover profile by
// package directory.
func parseProfile(file string) (map[string]*stat, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stats := make(map[string]*stat)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed profile line %q", line)
		}
		// fields[0] is "import/path/file.go:start,end".
		loc := fields[0]
		colon := strings.LastIndex(loc, ":")
		if colon < 0 {
			return nil, fmt.Errorf("malformed profile location %q", loc)
		}
		filePath := loc[:colon]
		pkg := path.Dir(filePath)

		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("malformed statement count in %q: %w", line, err)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("malformed execution count in %q: %w", line, err)
		}
		s := stats[pkg]
		if s == nil {
			s = &stat{}
			stats[pkg] = s
		}
		s.total += stmts
		if count > 0 {
			s.covered += stmts
		}
	}
	return stats, sc.Err()
}

type floorEntry struct {
	name  string
	floor float64
	skip  bool
}

func parseFloors(file string) ([]floorEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var floors []floorEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want `<package> <percent|skip>`", file, lineNo)
		}
		e := floorEntry{name: fields[0]}
		if fields[1] == "skip" {
			e.skip = true
		} else {
			v, err := strconv.ParseFloat(fields[1], 64)
			if err != nil || v < 0 || v > 100 {
				return nil, fmt.Errorf("%s:%d: invalid floor %q", file, lineNo, fields[1])
			}
			e.floor = v
		}
		floors = append(floors, e)
	}
	return floors, sc.Err()
}

func lookup(pkg string, floors []floorEntry, matched map[string]bool) (float64, bool, bool) {
	for _, e := range floors {
		if e.name == pkg || strings.HasSuffix(pkg, "/"+e.name) {
			matched[e.name] = true
			return e.floor, true, e.skip
		}
	}
	return 0, false, false
}

func floorNames(floors []floorEntry) []string {
	names := make([]string, 0, len(floors))
	for _, e := range floors {
		names = append(names, e.name)
	}
	return names
}
