package tier3_test

import (
	"strings"
	"testing"

	"github.com/aiss/agent/internal/security/tier3"
)

func newScorer() *tier3.Scorer {
	return tier3.NewScorer(tier3.BlockThreshold)
}

func TestScorer_CleanRequest_Permitted(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"GET", "/api/products", "category=electronics&page=1", "",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
		"application/json",
		map[string]string{"accept": "application/json"},
	)
	if result.Action == "BLOCK" {
		t.Errorf("clean request should be PERMIT, got BLOCK (score=%.3f reason=%s)",
			result.Score, result.Reason)
	}
}

func TestScorer_NullBytes_Blocked(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"GET", "/api/users\x00../admin", "", "",
		"Mozilla/5.0", "text/plain",
		map[string]string{},
	)
	if result.Action != "BLOCK" {
		t.Errorf("null byte in URI should be BLOCK, got %s (score=%.3f)", result.Action, result.Score)
	}
	if !strings.Contains(result.Reason, "null bytes") {
		t.Errorf("reason should mention null bytes, got: %s", result.Reason)
	}
}

func TestScorer_DoubleEncoding_Blocked(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"GET", "/%252e%252e/etc/passwd", "", "",
		"curl/7.68", "text/plain",
		map[string]string{},
	)
	if result.Action != "BLOCK" {
		t.Errorf("double-encoded path traversal should be BLOCK, got %s (score=%.3f)",
			result.Action, result.Score)
	}
}

func TestScorer_ScannerUA_Blocked(t *testing.T) {
	scanners := []string{
		"sqlmap/1.7 (https://sqlmap.org)",
		"Nikto/2.1.6",
		"Mozilla/5.0 (compatible; Googlebot/2.1) nikto",
		"python-requests/2.28.0 sqlmap",
	}
	scorer := newScorer()
	for _, ua := range scanners {
		result := scorer.Score("GET", "/", "", "", ua, "", map[string]string{})
		if result.Score < tier3.SuspiciousThreshold {
			t.Errorf("scanner UA %q scored only %.3f (below suspicious threshold)", ua, result.Score)
		}
	}
}

func TestScorer_ExcessiveParams_Flagged(t *testing.T) {
	scorer := newScorer()
	// 25 parameters — well above the threshold of 20
	params := strings.Repeat("key=value&", 25)
	result := scorer.Score(
		"POST", "/api/search", params[:len(params)-1], "",
		"Mozilla/5.0", "application/x-www-form-urlencoded",
		map[string]string{},
	)
	if result.Score == 0 {
		t.Error("excessive parameters should increase anomaly score")
	}
}

func TestScorer_EmptyUA_Scored(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score("GET", "/api/data", "", "", "", "", map[string]string{})
	if result.Score == 0 {
		t.Error("empty user-agent should add to anomaly score")
	}
}

func TestScorer_UnusualMethod_Scored(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"TRACE", "/api/debug", "", "",
		"Mozilla/5.0", "", map[string]string{},
	)
	if result.Score == 0 {
		t.Error("unusual HTTP method should increase anomaly score")
	}
}

func TestScorer_SuspiciousUA_Blocked(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"GET", "/api/data", "", "",
		"../../etc/passwd", "",
		map[string]string{},
	)
	if result.Action != "BLOCK" {
		t.Errorf("UA with path traversal should be BLOCK, got %s", result.Action)
	}
}

func TestScorer_LongURI_Scored(t *testing.T) {
	scorer := newScorer()
	longURI := "/api/" + strings.Repeat("a", 2500)
	result := scorer.Score("GET", longURI, "", "", "Mozilla/5.0", "", map[string]string{})
	if result.Score == 0 {
		t.Error("very long URI should increase anomaly score")
	}
}

func TestScorer_HighQueryEntropy_Scored(t *testing.T) {
	scorer := newScorer()
	// High entropy query = base64-like or obfuscated payload
	query := "q=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBoaWdoIGVudHJvcHkgc3RyaW5nIGZvciB0ZXN0aW5n"
	result := scorer.Score("GET", "/search", query, "", "Mozilla/5.0", "", map[string]string{})
	if result.Score == 0 {
		t.Error("high entropy query should increase anomaly score")
	}
}

func TestScorer_ShadowMode_NeverBlocks(t *testing.T) {
	// Shadow mode scorer with low threshold should still report BLOCK action
	// (shadow mode is applied at pipeline level, not scorer level)
	scorer := tier3.NewScorer(0.01) // Extremely low threshold → everything scores as BLOCK
	result := scorer.Score("GET", "/", "", "", "Mozilla/5.0", "", map[string]string{})
	if result.Action != "BLOCK" {
		t.Errorf("low threshold scorer should block, got %s (score=%.4f)", result.Action, result.Score)
	}
}

func TestScorer_Features_Populated(t *testing.T) {
	scorer := newScorer()
	result := scorer.Score(
		"POST", "/api/login", "username=admin",
		`{"password":"test"}`,
		"Mozilla/5.0", "application/json",
		map[string]string{"content-type": "application/json"},
	)
	f := result.Features
	if f.MethodEncoded != 1 { // POST = 1
		t.Errorf("expected MethodEncoded=1 (POST), got %.0f", f.MethodEncoded)
	}
	if f.URILength != float64(len("/api/login")) {
		t.Errorf("URILength mismatch")
	}
}

func BenchmarkScorer_CleanRequest(b *testing.B) {
	scorer := newScorer()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scorer.Score(
			"GET", "/api/products", "category=electronics&page=2", "",
			"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
			"application/json", map[string]string{"accept": "application/json"},
		)
	}
}

func BenchmarkScorer_AttackRequest(b *testing.B) {
	scorer := newScorer()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scorer.Score(
			"GET", "/%252e%252e/etc/passwd\x00", "",
			"admin'--",
			"sqlmap/1.7", "",
			map[string]string{},
		)
	}
}
