// Package content — YARA-compatible rule engine implemented in pure Go.
// Production: swap for go-yara (CGO + libYARA) for full YARA compatibility.
// This pure-Go implementation compiles YARA string definitions into regexp
// and applies the same boolean condition logic.
package content

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// YARAResult holds the outcome of a YARA scan.
type YARAResult struct {
	Matched     bool
	RuleName    string
	Namespace   string
	Severity    string
	Description string
}

// yaraRule is a compiled rule ready for scanning.
type yaraRule struct {
	name         string
	namespace    string
	severity     string
	description  string
	anyPatterns  []*regexp.Regexp
	countPattern *regexp.Regexp
	countMin     int
}

// YARAEngine is a thread-safe YARA rule engine.
type YARAEngine struct {
	mu    sync.RWMutex
	rules []*yaraRule
}

// NewYARAEngine loads all .yar files from rulesDir.
func NewYARAEngine(rulesDir string) (*YARAEngine, error) {
	e := &YARAEngine{}
	if err := e.Load(rulesDir); err != nil {
		return nil, err
	}
	return e, nil
}

// Load (re)compiles all rules. Safe to call while serving requests.
func (e *YARAEngine) Load(rulesDir string) error {
	files, err := filepath.Glob(filepath.Join(rulesDir, "*.yar"))
	if err != nil {
		return err
	}

	var rules []*yaraRule
	for _, f := range files {
		ns := strings.TrimSuffix(filepath.Base(f), ".yar")
		loaded, parseErr := parseYARFile(f, ns)
		if parseErr != nil {
			log.Warn().Str("file", f).Err(parseErr).Msg("skipping YARA file")
			continue
		}
		rules = append(rules, loaded...)
	}

	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()

	log.Info().Int("rules", len(rules)).Str("dir", rulesDir).Msg("YARA rules loaded")
	return nil
}

// Scan checks data against all loaded rules.
func (e *YARAEngine) Scan(data []byte) YARAResult {
	if len(data) == 0 {
		return YARAResult{}
	}
	text := string(data)

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	for _, rule := range rules {
		if ruleMatches(rule, text) {
			return YARAResult{
				Matched:     true,
				RuleName:    rule.name,
				Namespace:   rule.namespace,
				Severity:    rule.severity,
				Description: rule.description,
			}
		}
	}
	return YARAResult{}
}

// RuleCount returns the number of loaded rules.
func (e *YARAEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func ruleMatches(r *yaraRule, text string) bool {
	if r.countPattern != nil {
		return len(r.countPattern.FindAllString(text, -1)) >= r.countMin
	}
	for _, re := range r.anyPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// ── Minimal YARA .yar parser ───────────────────────────────────────────────

func parseYARFile(path, ns string) ([]*yaraRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []*yaraRule
	var current *yaraRule
	strDefs := map[string]*regexp.Regexp{}
	section := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "rule ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				current = &yaraRule{name: parts[1], namespace: ns, severity: "HIGH"}
				strDefs = map[string]*regexp.Regexp{}
				section = ""
			}
			continue
		}
		if current == nil {
			continue
		}

		switch line {
		case "meta:":
			section = "meta"
			continue
		case "strings:":
			section = "strings"
			continue
		case "condition:":
			section = "condition"
			continue
		case "}":
			if current.name != "" {
				if len(current.anyPatterns) == 0 && current.countPattern == nil {
					for _, re := range strDefs {
						current.anyPatterns = append(current.anyPatterns, re)
					}
				}
				rules = append(rules, current)
			}
			current = nil
			section = ""
			continue
		}

		switch section {
		case "meta":
			if strings.HasPrefix(line, "severity") {
				current.severity = extractMeta(line)
			} else if strings.HasPrefix(line, "description") {
				current.description = extractMeta(line)
			}

		case "strings":
			if !strings.HasPrefix(line, "$") {
				continue
			}
			idx := strings.Index(line, "=")
			if idx < 0 {
				continue
			}
			varName := strings.TrimSpace(line[:idx])
			rawPat := strings.TrimSpace(line[idx+1:])
			if re := compileYARAString(rawPat); re != nil {
				strDefs[varName] = re
			}

		case "condition":
			lower := strings.ToLower(line)
			if strings.Contains(lower, "any of") || strings.Contains(lower, "any of them") {
				for _, re := range strDefs {
					current.anyPatterns = append(current.anyPatterns, re)
				}
			} else if strings.HasPrefix(lower, "#") {
				applyCountCondition(lower, strDefs, current)
			} else {
				for varName, re := range strDefs {
					clean := strings.ToLower(strings.TrimPrefix(varName, "$"))
					if strings.Contains(lower, "$"+clean) || strings.Contains(lower, clean) {
						current.anyPatterns = append(current.anyPatterns, re)
					}
				}
			}
		}
	}
	return rules, scanner.Err()
}

func compileYARAString(raw string) *regexp.Regexp {
	nocase := strings.Contains(raw, " nocase") || strings.Contains(raw, "\tnocase")
	token := strings.Fields(raw)[0]

	var pattern string
	if strings.HasPrefix(token, "/") {
		last := strings.LastIndex(token, "/")
		if last <= 0 {
			return nil
		}
		pattern = token[1:last]
	} else {
		inner := strings.Trim(token, `"'`)
		pattern = regexp.QuoteMeta(inner)
	}

	if nocase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

func extractMeta(line string) string {
	if idx := strings.Index(line, "="); idx >= 0 {
		v := strings.TrimSpace(line[idx+1:])
		return strings.Trim(v, `"'`)
	}
	return ""
}

func applyCountCondition(line string, strDefs map[string]*regexp.Regexp, rule *yaraRule) {
	// e.g. "#email >= 10"
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return
	}
	varHint := strings.TrimPrefix(parts[0], "#")
	minCount, err := strconv.Atoi(parts[2])
	if err != nil {
		return
	}
	_ = fmt.Sprintf // ensure fmt is used
	for varName, re := range strDefs {
		if strings.Contains(strings.ToLower(varName), varHint) {
			rule.countPattern = re
			rule.countMin = minCount
			return
		}
	}
}
