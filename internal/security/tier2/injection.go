// Package tier2 implements structural SQL injection and XSS detection.
// Production equivalent: Libinjection (structural parse, not pure regex).
// This uses a grammar-rule approach: tokenise → match dangerous SQL/XSS constructs.
package tier2

import (
	"net/url"
	"regexp"
	"strings"
)

// Result holds the outcome of a Tier 2 injection check.
type Result struct {
	Detected    bool
	Type        string // "sqli" | "xss"
	Fingerprint string
	Detail      string
}

// ── SQL Injection patterns ─────────────────────────────────────────────────

var (
	// Structural patterns (most reliable — grammar-level)
	sqlStructural = regexp.MustCompile(`(?i)` +
		`(` +
		`'[\s]*(?:or|and)[\s]+['"\d]` + `|` + // ' or '1 / ' and 1
		`union[\s]+(?:all[\s]+)?select` + `|` + // UNION SELECT
		`;[\s]*(?:drop|alter|create|exec|insert|delete|update)` + `|` + // stacked
		`(?:--|#)[\s]*$` + `|` + // trailing comment
		`xp_cmdshell` + `|` + // MSSQL
		`information_schema\.(?:tables|columns)` + `|` + // schema enum
		`sleep[\s]*\([\s]*\d+[\s]*\)` + `|` + // MySQL time-based
		`waitfor[\s]+delay` + `|` + // MSSQL time-based
		`benchmark[\s]*\(` + `|` + // MySQL benchmark
		`load_file[\s]*\(` + `|` + // MySQL file read
		`into[\s]+outfile` + // MySQL file write
		`)`)

	// Tautology: ' OR 1=1 / AND 1='1'
	sqlTautology = regexp.MustCompile(`(?i)(\bor\b|\band\b)[\s]+[\w'"]+[\s]*=[\s]*[\w'"]+`)

	// Comment sequences
	sqlComment = regexp.MustCompile(`(?i)(--|#|/\*|\*/)`)

	// Quote injection
	sqlQuote = regexp.MustCompile(`(?i)['"]\s*(or|and|union|select|exec)`)

	// Numeric tautologies: 1=1, 2=2, 0=0, etc.
	// Go's RE2 engine does not support backreferences, so we match any
	// digit sequence repeated on both sides and verify equality in code.
	sqlNumericTauto = regexp.MustCompile(`\b(\d+)\s*=\s*(\d+)\b`)
)

// CheckSQLi checks all input strings for SQL injection.
func CheckSQLi(inputs []string) Result {
	for _, raw := range inputs {
		for _, text := range variants(raw) {
			if m := sqlStructural.FindString(text); m != "" {
				return Result{
					Detected:    true,
					Type:        "sqli",
					Fingerprint: m,
					Detail:      "SQL injection: structural match '" + truncate(m, 80) + "'",
				}
			}
			if sqlTautology.MatchString(text) && sqlComment.MatchString(text) {
				return Result{
					Detected:    true,
					Type:        "sqli",
					Fingerprint: "tautology+comment",
					Detail:      "SQL injection: logical tautology with comment",
				}
			}
			// Numeric tautology: both sides must be equal (e.g. 1=1, 42=42).
			// RE2 has no backreferences, so we verify equality in code.
			if sub := sqlNumericTauto.FindStringSubmatch(text); len(sub) == 3 && sub[1] == sub[2] {
				return Result{
					Detected:    true,
					Type:        "sqli",
					Fingerprint: sub[0],
					Detail:      "SQL injection: numeric tautology '" + sub[0] + "'",
				}
			}
		}
	}
	return Result{}
}

// ── XSS patterns ──────────────────────────────────────────────────────────

var (
	xssScript = regexp.MustCompile(`(?i)<[\s]*(script)[^>]*>`)

	xssJavascript = regexp.MustCompile(`(?i)javascript[\s]*:`)

	xssEvents = regexp.MustCompile(
		`(?i)\bon(load|error|click|mouseover|mouseout|focus|blur|submit|` +
			`keydown|keyup|keypress|change|input|resize|scroll|dblclick|` +
			`contextmenu|drag|drop|copy|paste|cut|unload|beforeunload)[\s]*=`)

	xssDataURI = regexp.MustCompile(
		`(?i)data[\s]*:[\s]*(text/html|application/javascript|text/javascript)`)

	xssSVG = regexp.MustCompile(
		`(?is)<[\s]*svg[^>]*>.*?(onload|onerror|onclick)`)

	xssExpression = regexp.MustCompile(`(?i)(expression[\s]*\(|vbscript[\s]*:)`)

	xssEntities = regexp.MustCompile(
		`(?i)(&lt;script|&#60;script|%3Cscript|\\u003cscript|%253Cscript)`)
)

// CheckXSS checks all input strings for Cross-Site Scripting patterns.
func CheckXSS(inputs []string) Result {
	for _, raw := range inputs {
		for _, text := range variants(raw) {
			if m := xssScript.FindString(text); m != "" {
				return Result{Detected: true, Type: "xss", Fingerprint: "script_tag",
					Detail: "XSS: script tag '" + truncate(m, 60) + "'"}
			}
			if xssJavascript.MatchString(text) {
				return Result{Detected: true, Type: "xss", Fingerprint: "javascript_proto",
					Detail: "XSS: javascript: protocol injection"}
			}
			if m := xssEvents.FindString(text); m != "" {
				return Result{Detected: true, Type: "xss", Fingerprint: "event_handler",
					Detail: "XSS: DOM event handler '" + truncate(m, 60) + "'"}
			}
			if xssDataURI.MatchString(text) {
				return Result{Detected: true, Type: "xss", Fingerprint: "data_uri",
					Detail: "XSS: data: URI injection"}
			}
			if xssSVG.MatchString(text) {
				return Result{Detected: true, Type: "xss", Fingerprint: "svg_xss",
					Detail: "XSS: SVG-based attack"}
			}
			if xssExpression.MatchString(text) {
				return Result{Detected: true, Type: "xss", Fingerprint: "css_expression",
					Detail: "XSS: CSS expression() injection"}
			}
			if xssEntities.MatchString(text) {
				return Result{Detected: true, Type: "xss", Fingerprint: "encoded_xss",
					Detail: "XSS: HTML/URL-encoded script tag"}
			}
		}
	}
	return Result{}
}

// ExtractInputs returns all injectable surfaces from an HTTP request map.
func ExtractInputs(req map[string]interface{}) []string {
	var inputs []string
	add := func(s string) {
		if s != "" {
			inputs = append(inputs, s)
		}
	}

	add(strVal(req, "uri"))
	add(strVal(req, "query_string"))

	if headers, ok := req["headers"].(map[string]string); ok {
		for _, h := range []string{"user-agent", "referer", "x-forwarded-for", "cookie", "host"} {
			add(headers[h])
		}
	}

	body := strVal(req, "body")
	add(body)
	if ct := strVal(req, "content_type"); strings.Contains(ct, "x-www-form-urlencoded") {
		for _, part := range strings.Split(body, "&") {
			if idx := strings.Index(part, "="); idx >= 0 {
				add(part[idx+1:])
			}
		}
	}
	return inputs
}

// ── Helpers ───────────────────────────────────────────────────────────────

// variants returns [original, url-decoded, double-decoded] for bypass detection.
func variants(s string) []string {
	out := []string{s}
	dec, err := url.QueryUnescape(s)
	if err == nil && dec != s {
		out = append(out, dec)
		dec2, err2 := url.QueryUnescape(dec)
		if err2 == nil && dec2 != dec {
			out = append(out, dec2)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
