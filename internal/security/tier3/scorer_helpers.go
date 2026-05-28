package tier3

// scorer_helpers.go — shared feature extraction helpers used by both
// the heuristic scorer (scorer_heuristic.go) and the ONNX scorer (scorer_onnx.go).
// This file has NO build tags so it is always compiled.

import (
	"math"
	"regexp"
	"strings"
)

// ── Pre-compiled Regexps ──────────────────────────────────────────────────

var (
	reUnicode = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

	reScannerUA = regexp.MustCompile(
		`(?i)(nmap|nikto|sqlmap|masscan|zgrab|gobuster|dirbuster|wfuzz|` +
			`burpsuite|acunetix|nessus|openvas|w3af|skipfish|havij|` +
			`hydra|medusa|metasploit|python-requests|go-http-client|` +
			`libwww-perl|wget/|scrapy|mechanize|phantomjs|headlesschrome)`)

	reSuspiciousUA = regexp.MustCompile(
		`(?i)(\.\./|<script|select\s+from|union\s+select|eval\(|base64_decode)`)

	reSpecialChars = regexp.MustCompile(`[!@#$%^&*()\[\]{}|\\<>/?;:'"` + "`" + `]`)
)

// ── Feature Extraction ────────────────────────────────────────────────────

func extractFeatures(method, uri, query, body, ua, ct string, headers map[string]string) Features {
	full := uri + " " + query + " " + body
	return Features{
		MethodEncoded:    encodeMethod(method),
		URILength:        float64(len(uri)),
		QueryLength:      float64(len(query)),
		HeaderCount:      float64(len(headers)),
		BodyLength:       float64(len(body)),
		URIEntropy:       shannonEntropy(uri),
		QueryEntropy:     shannonEntropy(query),
		BodyEntropy:      shannonEntropy(body),
		SpecialCharRatio: specialCharRatio(full),
		EncodedCharCount: float64(strings.Count(full, "%")),
		DoubleEncoded:    boolF(strings.Contains(full, "%25")),
		NullBytes:        boolF(strings.Contains(full, "\x00") || strings.Contains(full, "%00")),
		UnicodeEscape:    boolF(reUnicode.MatchString(full)),
		HasBase64Body:    boolF(reBase64.MatchString(body)),
		ParamCount:       float64(strings.Count(full, "=")),
		ExcessiveParams:  boolF(strings.Count(full, "=") > 20),
		UALength:         float64(len(ua)),
		UAIsScanner:      boolF(reScannerUA.MatchString(ua)),
		UAEmpty:          boolF(ua == ""),
		UASuspicious:     boolF(reSuspiciousUA.MatchString(ua)),
		UnusualMethod:    boolF(!isCommonMethod(method)),
		HasProxyHeaders:  boolF(hasProxyHeaders(headers)),
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return roundTo(h, 4)
}

func specialCharRatio(s string) float64 {
	if s == "" {
		return 0
	}
	matches := reSpecialChars.FindAllString(s, -1)
	return roundTo(float64(len(matches))/float64(len(s)), 4)
}

func encodeMethod(m string) float64 {
	switch strings.ToUpper(m) {
	case "GET":
		return 0
	case "POST":
		return 1
	case "PUT":
		return 2
	case "DELETE":
		return 3
	case "PATCH":
		return 4
	case "HEAD":
		return 5
	case "OPTIONS":
		return 6
	default:
		return 7
	}
}

func isCommonMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func hasProxyHeaders(headers map[string]string) bool {
	for _, h := range []string{"via", "forwarded", "x-real-ip", "x-originating-ip"} {
		if _, ok := headers[h]; ok {
			return true
		}
	}
	return false
}

func boolF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func roundTo(v float64, places int) float64 {
	pow := math.Pow10(places)
	return math.Round(v*pow) / pow
}

// ── heuristicScorer ───────────────────────────────────────────────────────
// Defined here (no build tag) so it is available to both scorer_heuristic.go
// (which provides newScorerImpl when !onnx) and scorer_onnx.go (which uses it
// as a fallback when the ONNX model cannot be loaded).

// heuristicScorer is the rule-based anomaly scorer implementation.
type heuristicScorer struct {
	Threshold float64
}

// score computes an anomaly score using the heuristic rules.
func (s *heuristicScorer) score(
	method, uri, query, body, userAgent, contentType string,
	headers map[string]string,
) Result {
	f := extractFeatures(method, uri, query, body, userAgent, contentType, headers)
	sc, reasons := computeScore(f)

	action := "PERMIT"
	if sc >= s.Threshold {
		action = "BLOCK"
	} else if sc >= SuspiciousThreshold {
		action = "SUSPICIOUS"
	}

	return Result{
		Score:    roundTo(sc, 4),
		Action:   action,
		Features: f,
		Reason:   strings.Join(reasons, "; "),
	}
}

// ── Scoring Logic ─────────────────────────────────────────────────────────
// computeScore is here (not in scorer_heuristic.go) so it is always compiled
// and available to heuristicScorer regardless of build tags.

func computeScore(f Features) (float64, []string) {
	var total float64
	var reasons []string

	add := func(weight float64, reason string) {
		total += weight
		reasons = append(reasons, reason)
	}

	if f.NullBytes > 0 {
		add(0.70, "null bytes in request")
	}
	if f.DoubleEncoded > 0 {
		add(0.50, "double URL encoding — bypass attempt")
	}
	if f.EncodedCharCount > 30 {
		add(0.25, "excessive URL encoding")
	}
	if f.URILength > 2000 {
		add(0.40, "suspicious URI length")
	} else if f.URILength > 1000 {
		add(0.20, "long URI")
	}
	if f.QueryEntropy > 4.5 {
		add(0.30, "high query string entropy — obfuscated payload")
	}
	if f.BodyEntropy > 5.5 && f.BodyLength > 100 {
		add(0.25, "high body entropy — obfuscated content")
	}
	if f.UAIsScanner > 0 {
		add(0.35, "known security scanner user-agent")
	}
	if f.UASuspicious > 0 {
		add(0.40, "suspicious user-agent pattern")
	}
	if f.UAEmpty > 0 {
		add(0.15, "empty user-agent")
	}
	if f.UnusualMethod > 0 {
		add(0.20, "unusual HTTP method")
	}
	if f.HasBase64Body > 0 {
		add(0.20, "Base64-encoded content in body")
	}
	if f.ExcessiveParams > 0 {
		add(0.20, "excessive parameter count")
	}
	if f.SpecialCharRatio > 0.15 {
		add(0.30, "high special character ratio")
	}
	if f.HasProxyHeaders > 0 && total > 0.2 {
		add(0.10, "proxy headers with suspicious activity")
	}
	if f.UnicodeEscape > 0 {
		add(0.20, "unicode escape sequences")
	}

	return math.Min(total, 1.0), reasons
}
