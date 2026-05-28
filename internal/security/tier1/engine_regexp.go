//go:build !hyperscan

// Package tier1 implements CVE signature matching using compiled regexp patterns.
// Production equivalent: Intel Hyperscan (multi-pattern, simultaneous scan).
// All patterns are compiled ONCE at startup — never per-request.
package tier1

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"

	"github.com/rs/zerolog/log"
)

// engineRegexp is the regexp-backed implementation of engineImpl.
type engineRegexp struct {
	mu       sync.RWMutex
	patterns []*cvePatternCompiled
}

// cvePatternCompiled wraps CVEPattern with a compiled regexp.
type cvePatternCompiled struct {
	*CVEPattern
	compiled *regexp.Regexp
}

// newImpl returns the regexp-backed engine (used when the hyperscan build tag is absent).
func newImpl() engineImpl { return &engineRegexp{} }

// load (re)loads and compiles patterns. Safe to call while serving requests.
func (e *engineRegexp) load(patternsFile string) error {
	data, err := os.ReadFile(patternsFile)
	if err != nil {
		return fmt.Errorf("reading patterns file %s: %w", patternsFile, err)
	}

	var raw []*CVEPattern
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing patterns JSON: %w", err)
	}

	compiled := make([]*cvePatternCompiled, 0, len(raw))
	skipped := 0
	for _, p := range raw {
		flags := regexp.MustCompilePOSIX // base flags
		_ = flags
		var re *regexp.Regexp
		var compErr error
		if containsIgnoreCase(p.Flags) {
			re, compErr = regexp.Compile("(?i)" + p.Pattern)
		} else {
			re, compErr = regexp.Compile(p.Pattern)
		}
		if compErr != nil {
			log.Warn().Str("cve", p.CVEID).Str("pattern", p.Pattern).
				Err(compErr).Msg("skipping invalid CVE pattern")
			skipped++
			continue
		}
		compiled = append(compiled, &cvePatternCompiled{CVEPattern: p, compiled: re})
	}

	// Sort CRITICAL first so we short-circuit on the worst match
	sort.Slice(compiled, func(i, j int) bool {
		return severityOrder(compiled[i].Severity) < severityOrder(compiled[j].Severity)
	})

	e.mu.Lock()
	e.patterns = compiled
	e.mu.Unlock()

	log.Info().
		Int("loaded", len(compiled)).
		Int("skipped", skipped).
		Msg("CVE patterns loaded")
	return nil
}

// scan checks data against all compiled CVE patterns.
// Returns on first match (short-circuit, highest severity first).
func (e *engineRegexp) scan(data string) Result {
	if data == "" {
		return Result{}
	}

	e.mu.RLock()
	patterns := e.patterns
	e.mu.RUnlock()

	for _, p := range patterns {
		if p.compiled.MatchString(data) {
			return Result{
				Matched:     true,
				CVEID:       p.CVEID,
				Name:        p.Name,
				Severity:    p.Severity,
				CVSS:        p.CVSS,
				Description: p.Description,
			}
		}
	}
	return Result{}
}

// patternCount returns the number of loaded patterns.
func (e *engineRegexp) patternCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.patterns)
}
