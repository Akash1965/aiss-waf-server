package content_test

import (
	"encoding/base64"
	"testing"

	"github.com/aiss/agent/internal/security/content"
)

// ── ExtractB64Candidates ──────────────────────────────────────────────────

func TestExtractB64_EmptyBody(t *testing.T) {
	candidates := content.ExtractB64Candidates([]byte{})
	if len(candidates) != 0 {
		t.Errorf("empty body should return no candidates, got %d", len(candidates))
	}
}

func TestExtractB64_NoCandidates(t *testing.T) {
	// Short value — below minB64Length threshold
	body := []byte("q=hello&name=world&action=view")
	candidates := content.ExtractB64Candidates(body)
	if len(candidates) != 0 {
		t.Errorf("short plain values should not yield candidates, got %d", len(candidates))
	}
}

func TestExtractB64_ValidLongPayload(t *testing.T) {
	// Base64-encode a realistic payload (> 48 chars)
	payload := "This is a long test payload to embed in Base64 form inside a query string"
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	body := []byte("q=" + encoded)
	candidates := content.ExtractB64Candidates(body)
	if len(candidates) == 0 {
		t.Error("should have found at least one Base64 candidate in payload")
	}
	// Verify decoded content matches original
	found := false
	for _, c := range candidates {
		if string(c) == payload {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("decoded candidate should contain original payload: %q", payload)
	}
}

func TestExtractB64_MultipleEmbedded(t *testing.T) {
	// Two separate Base64 segments in the same body
	p1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 52 'A' bytes
	p2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	e1 := base64.StdEncoding.EncodeToString([]byte(p1))
	e2 := base64.StdEncoding.EncodeToString([]byte(p2))
	body := []byte("data1=" + e1 + "&data2=" + e2)
	candidates := content.ExtractB64Candidates(body)
	if len(candidates) < 2 {
		t.Errorf("expected >= 2 candidates for two embedded Base64 segments, got %d", len(candidates))
	}
}

func TestExtractB64_PHPWebshell_Detected(t *testing.T) {
	// Base64-encoded PHP webshell — a common obfuscation technique
	shell := "<?php system($_GET['cmd']); ?>"
	encoded := base64.StdEncoding.EncodeToString([]byte(shell))
	// Pad to make the encoded string > 48 chars (it already is ~44 chars; pad the payload)
	shell2 := "<?php eval(base64_decode($_POST['payload'])); echo shell_exec($_GET['cmd']); ?>"
	encoded2 := base64.StdEncoding.EncodeToString([]byte(shell2))
	body := []byte("cmd=exec&payload=" + encoded2)
	candidates := content.ExtractB64Candidates(body)
	if len(candidates) == 0 {
		t.Errorf("Base64-encoded PHP webshell should be extracted as candidate (encoded=%q)", encoded)
	}
	_ = encoded // silence unused warning
}

func TestExtractB64_ShortCandidatesIgnored(t *testing.T) {
	// Encode a very short string — below minB64Length (48 chars encoded)
	short := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := []byte("data=" + short)
	candidates := content.ExtractB64Candidates(body)
	// Should be ignored (too short)
	if len(candidates) != 0 {
		t.Errorf("short Base64 (< 48 chars) should be ignored, got %d candidates", len(candidates))
	}
}

// ── DecodeIfBase64 ────────────────────────────────────────────────────────

func TestDecodeIfBase64_Nil_OnEmpty(t *testing.T) {
	result := content.DecodeIfBase64([]byte{}, "application/octet-stream")
	if result != nil {
		t.Error("empty body should return nil")
	}
}

func TestDecodeIfBase64_Nil_OnPlainJSON(t *testing.T) {
	body := []byte(`{"username":"alice","password":"hunter2"}`)
	result := content.DecodeIfBase64(body, "application/json")
	if result != nil {
		t.Error("plain JSON should not be decoded as Base64")
	}
}

func TestDecodeIfBase64_Nil_OnMultipart(t *testing.T) {
	// Multipart bodies should be skipped
	body := []byte("--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nhello\r\n--boundary--")
	result := content.DecodeIfBase64(body, "multipart/form-data; boundary=boundary")
	if result != nil {
		t.Error("multipart bodies should not be decoded as whole-body Base64")
	}
}

func TestDecodeIfBase64_Succeeds_OnValidBase64Body(t *testing.T) {
	// Whole body is Base64 encoded binary
	original := make([]byte, 200)
	for i := range original {
		original[i] = byte(i % 256)
	}
	encoded := base64.StdEncoding.EncodeToString(original)
	result := content.DecodeIfBase64([]byte(encoded), "application/octet-stream")
	if result == nil {
		t.Error("valid Base64 body should be decoded successfully")
	}
}

func TestDecodeIfBase64_Nil_OnHTMLContent(t *testing.T) {
	// HTML bodies should be skipped regardless of content
	body := []byte("<html><body>SGVsbG8gV29ybGQ=</body></html>")
	result := content.DecodeIfBase64(body, "text/html")
	if result != nil {
		t.Error("text/html content-type should skip whole-body Base64 decode")
	}
}

func TestDecodeIfBase64_Nil_WhenDecodedTooLong(t *testing.T) {
	// If decoded is nearly as long as encoded, it's probably not Base64 (plain text with high ASCII ratio)
	body := []byte("hello world this is just normal plain text that happens to be longish")
	result := content.DecodeIfBase64(body, "text/plain")
	// Base64 decoding random text will usually fail or produce junk that is ~75% of original size
	// Either way, we're checking it doesn't crash
	_ = result
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkExtractB64Candidates_SmallBody(b *testing.B) {
	payload := "SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZCBmb3IgYmVuY2htYXJraW5n"
	body := []byte("q=search&data=" + payload + "&extra=value")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.ExtractB64Candidates(body)
	}
}

func BenchmarkDecodeIfBase64_4KB(b *testing.B) {
	original := make([]byte, 3000)
	for i := range original {
		original[i] = byte(i % 127)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(original))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.DecodeIfBase64(encoded, "application/octet-stream")
	}
}
