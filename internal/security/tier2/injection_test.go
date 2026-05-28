package tier2_test

import (
	"testing"

	"github.com/aiss/agent/internal/security/tier2"
)

// ── SQL Injection Tests ────────────────────────────────────────────────────

func TestCheckSQLi_Detected(t *testing.T) {
	attacks := []struct {
		name  string
		input string
	}{
		{"UNION SELECT", `1' UNION SELECT username,password FROM users--`},
		{"OR tautology", `admin'--`},
		{"OR 1=1 comment", `' OR 1=1--`},
		{"stacked drop", `1; DROP TABLE users`},
		{"time-based sleep", `1; SELECT SLEEP(5)--`},
		{"MSSQL xp_cmdshell", `1; EXEC xp_cmdshell('whoami')--`},
		{"schema enumeration", `' UNION SELECT table_name FROM information_schema.tables--`},
		{"numeric tautology", `1=1`},
		{"waitfor delay", `'; WAITFOR DELAY '0:0:5'--`},
		{"stacked exec", `1; EXEC('SELECT 1')--`},
		{"load_file", `' UNION SELECT load_file('/etc/passwd')--`},
		{"URL-encoded SQLi", `%27%20OR%201%3D1--`},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			result := tier2.CheckSQLi([]string{tt.input})
			if !result.Detected {
				t.Errorf("SQLi not detected in: %q", tt.input)
			}
			if result.Type != "sqli" {
				t.Errorf("expected type 'sqli', got %q", result.Type)
			}
		})
	}
}

func TestCheckSQLi_CleanInputs(t *testing.T) {
	clean := []struct {
		name  string
		input string
	}{
		{"normal search", `search=golang tutorial`},
		{"email address", `user@example.com`},
		{"normal id", `id=42`},
		{"product name", `name=laptop 15 inch`},
		{"date range", `from=2024-01-01&to=2024-12-31`},
		{"JSON body", `{"username":"alice","age":30}`},
		{"path param", `/api/users/42/orders`},
		{"select word in content", `please select your preferred option`},
		{"order clause without injection", `order by price`},
	}

	for _, tt := range clean {
		t.Run(tt.name, func(t *testing.T) {
			result := tier2.CheckSQLi([]string{tt.input})
			if result.Detected {
				t.Errorf("false positive SQLi on clean input %q: %s", tt.input, result.Detail)
			}
		})
	}
}

// ── XSS Tests ─────────────────────────────────────────────────────────────

func TestCheckXSS_Detected(t *testing.T) {
	attacks := []struct {
		name  string
		input string
	}{
		{"script tag", `<script>alert('XSS')</script>`},
		{"script with src", `<script src="http://evil.com/x.js"></script>`},
		{"javascript protocol", `<a href="javascript:alert(1)">click</a>`},
		{"onerror handler", `<img src=x onerror=alert(1)>`},
		{"onload handler", `<body onload=alert(1)>`},
		{"onclick handler", `<div onclick="document.cookie">click</div>`},
		{"data URI HTML", `<iframe src="data:text/html,<script>alert(1)</script>">`},
		{"SVG onload", `<svg onload=alert(1)>`},
		{"CSS expression", `<div style="width:expression(alert(1))">`},
		{"HTML-encoded script", `&lt;script&gt;alert(1)&lt;/script&gt;`},
		{"URL-encoded XSS", `%3Cscript%3Ealert(1)%3C/script%3E`},
		{"vbscript protocol", `<a href="vbscript:msgbox(1)">x</a>`},
		{"onmouseover", `<div onmouseover="alert(document.domain)">`},
	}

	for _, tt := range attacks {
		t.Run(tt.name, func(t *testing.T) {
			result := tier2.CheckXSS([]string{tt.input})
			if !result.Detected {
				t.Errorf("XSS not detected in: %q", tt.input)
			}
			if result.Type == "" {
				t.Error("expected non-empty XSS type")
			}
		})
	}
}

func TestCheckXSS_CleanInputs(t *testing.T) {
	clean := []struct {
		name  string
		input string
	}{
		{"normal text", `Hello World`},
		{"HTML paragraph", `<p>This is a paragraph.</p>`},
		{"anchor tag", `<a href="https://example.com">link</a>`},
		{"image tag safe", `<img src="/logo.png" alt="logo">`},
		{"JSON", `{"key": "value"}`},
		{"markdown", `# Title\n\n**Bold text**`},
		{"email", `user@example.com`},
		{"URL", `https://example.com/path?q=hello`},
	}

	for _, tt := range clean {
		t.Run(tt.name, func(t *testing.T) {
			result := tier2.CheckXSS([]string{tt.input})
			if result.Detected {
				t.Errorf("false positive XSS on: %q (%s)", tt.input, result.Detail)
			}
		})
	}
}

// ── Multiple inputs ────────────────────────────────────────────────────────

func TestCheckSQLi_MultipleInputs(t *testing.T) {
	inputs := []string{
		`normal string`,
		`another clean value`,
		`' UNION SELECT * FROM users--`, // attack in the third input
	}
	result := tier2.CheckSQLi(inputs)
	if !result.Detected {
		t.Error("SQLi not detected in multi-input check")
	}
}

func TestCheckXSS_MultipleInputs(t *testing.T) {
	inputs := []string{
		`normal`,
		`<p>safe html</p>`,
		`<script>evil()</script>`, // attack in third input
	}
	result := tier2.CheckXSS(inputs)
	if !result.Detected {
		t.Error("XSS not detected in multi-input check")
	}
}

// ── URL-decode bypass ─────────────────────────────────────────────────────

func TestSQLi_URLEncodedBypass(t *testing.T) {
	// Attacker URL-encodes the payload to bypass naive string checks
	encoded := `%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--`
	result := tier2.CheckSQLi([]string{encoded})
	if !result.Detected {
		t.Error("URL-encoded SQLi bypass not detected")
	}
}

func TestXSS_URLEncodedBypass(t *testing.T) {
	encoded := `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`
	result := tier2.CheckXSS([]string{encoded})
	if !result.Detected {
		t.Error("URL-encoded XSS bypass not detected")
	}
}

// ── OWASP Top 10 coverage ─────────────────────────────────────────────────

func TestOWASP_A03_InjectionCoverage(t *testing.T) {
	// All OWASP A03:2021 Injection test cases
	cases := []string{
		`' OR '1'='1`,
		`1; DROP TABLE students;--`,
		`admin'--`,
		`1' AND 1=1--`,
		`UNION ALL SELECT NULL--`,
		`') OR ('1'='1`,
		`1'; INSERT INTO logs VALUES('hacked')--`,
	}
	for _, c := range cases {
		result := tier2.CheckSQLi([]string{c})
		if !result.Detected {
			t.Errorf("OWASP A03 SQLi missed: %q", c)
		}
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkCheckSQLi_NoMatch(b *testing.B) {
	inputs := []string{`search=laptop&category=electronics&page=1`}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tier2.CheckSQLi(inputs)
	}
}

func BenchmarkCheckSQLi_Match(b *testing.B) {
	inputs := []string{`' UNION SELECT username,password FROM users--`}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tier2.CheckSQLi(inputs)
	}
}

func BenchmarkCheckXSS_NoMatch(b *testing.B) {
	inputs := []string{`<p>This is a completely safe paragraph with normal HTML content</p>`}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tier2.CheckXSS(inputs)
	}
}
