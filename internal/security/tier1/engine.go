package tier1

// CVEPattern holds a compiled CVE signature.
type CVEPattern struct {
	ID              int     `json:"id"`
	CVEID           string  `json:"cve_id"`
	Name            string  `json:"name"`
	Severity        string  `json:"severity"`
	CVSS            float64 `json:"cvss"`
	Pattern         string  `json:"pattern"`
	Flags           string  `json:"flags"`
	AffectedProduct string  `json:"affected_product"`
	Description     string  `json:"description"`
}

// Result holds the outcome of a Tier 1 scan.
type Result struct {
	Matched     bool
	CVEID       string
	Name        string
	Severity    string
	CVSS        float64
	Description string
}

// engineImpl is the interface that both regexp and Hyperscan backends satisfy.
type engineImpl interface {
	load(patternsFile string) error
	scan(data string) Result
	patternCount() int
}

// Engine is the CVE pattern matching interface.
// Implementations: engineRegexp (default), engineHyperscan (build tag: hyperscan).
type Engine struct {
	impl engineImpl
}

// NewEngine creates an Engine backed by the available implementation.
func NewEngine(patternsFile string) (*Engine, error) {
	impl := newImpl()
	if err := impl.load(patternsFile); err != nil {
		return nil, err
	}
	return &Engine{impl: impl}, nil
}

// Scan checks data against all compiled CVE patterns.
func (e *Engine) Scan(data string) Result { return e.impl.scan(data) }

// PatternCount returns the number of loaded patterns.
func (e *Engine) PatternCount() int { return e.impl.patternCount() }

// Load (re)loads patterns from the given JSON file. Safe to call while serving requests.
func (e *Engine) Load(patternsFile string) error { return e.impl.load(patternsFile) }

// severityOrder returns a sort key so CRITICAL patterns are checked first.
func severityOrder(s string) int {
	switch s {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	default:
		return 3
	}
}

// containsIgnoreCase reports whether the flags string requests case-insensitive matching.
func containsIgnoreCase(flags string) bool {
	return flags == "CASELESS" || flags == "IGNORECASE"
}
