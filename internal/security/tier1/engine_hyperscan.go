//go:build hyperscan

package tier1

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/flier/gohs/hyperscan"
	"github.com/rs/zerolog/log"
)

type engineHyperscan struct {
	mu       sync.RWMutex
	db       hyperscan.BlockDatabase
	scratch  *hyperscan.Scratch // prototype scratch, cloned per goroutine
	pool     sync.Pool          // pool of *hyperscan.Scratch
	patterns []*CVEPattern      // metadata for result lookup
}

func newImpl() engineImpl { return &engineHyperscan{} }

func (e *engineHyperscan) load(patternsFile string) error {
	data, err := os.ReadFile(patternsFile)
	if err != nil {
		return fmt.Errorf("reading patterns file: %w", err)
	}
	var raw []*CVEPattern
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parsing patterns JSON: %w", err)
	}

	// Sort CRITICAL first
	sort.Slice(raw, func(i, j int) bool {
		return severityOrder(raw[i].Severity) < severityOrder(raw[j].Severity)
	})

	// Build Hyperscan patterns
	hsPatterns := make([]*hyperscan.Pattern, 0, len(raw))
	valid := make([]*CVEPattern, 0, len(raw))
	for idx, p := range raw {
		flags := hyperscan.SomLeftMost
		if containsIgnoreCase(p.Flags) {
			flags |= hyperscan.Caseless
		}
		hp, err := hyperscan.ParsePattern(fmt.Sprintf("%d:/%s/", idx, p.Pattern))
		if err != nil {
			log.Warn().Str("cve", p.CVEID).Err(err).Msg("Hyperscan: skipping invalid pattern")
			continue
		}
		hp.Flags = flags
		hsPatterns = append(hsPatterns, hp)
		valid = append(valid, p)
	}

	db, err := hyperscan.NewBlockDatabase(hsPatterns...)
	if err != nil {
		return fmt.Errorf("building Hyperscan database: %w", err)
	}

	scratch, err := hyperscan.NewScratch(db)
	if err != nil {
		db.Close()
		return fmt.Errorf("allocating Hyperscan scratch: %w", err)
	}

	e.mu.Lock()
	if e.db != nil {
		e.db.Close()
	}
	if e.scratch != nil {
		e.scratch.Free()
	}
	e.db = db
	e.scratch = scratch
	e.patterns = valid
	e.pool = sync.Pool{
		New: func() interface{} {
			s, _ := scratch.Clone()
			return s
		},
	}
	e.mu.Unlock()

	log.Info().Int("loaded", len(valid)).Msg("Hyperscan CVE patterns compiled")
	return nil
}

func (e *engineHyperscan) scan(data string) Result {
	if data == "" {
		return Result{}
	}

	e.mu.RLock()
	db := e.db
	patterns := e.patterns
	e.mu.RUnlock()

	if db == nil || len(patterns) == 0 {
		return Result{}
	}

	scratch := e.pool.Get().(*hyperscan.Scratch)
	defer e.pool.Put(scratch)

	var matched Result
	err := db.Scan([]byte(data), scratch, func(id uint, from, to uint64, flags uint, ctx interface{}) error {
		if int(id) < len(patterns) {
			p := patterns[id]
			matched = Result{
				Matched:     true,
				CVEID:       p.CVEID,
				Name:        p.Name,
				Severity:    p.Severity,
				CVSS:        p.CVSS,
				Description: p.Description,
			}
		}
		return hyperscan.ErrScanTerminated // stop after first match
	}, nil)

	if err != nil && err != hyperscan.ErrScanTerminated {
		log.Debug().Err(err).Msg("Hyperscan scan error")
	}
	return matched
}

func (e *engineHyperscan) patternCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.patterns)
}
