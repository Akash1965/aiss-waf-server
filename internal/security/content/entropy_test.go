package content_test

import (
	"math"
	"strings"
	"testing"

	"github.com/aiss/agent/internal/security/content"
)

// ── ShannonEntropy ────────────────────────────────────────────────────────

func TestShannonEntropy_Empty(t *testing.T) {
	if h := content.ShannonEntropy([]byte{}); h != 0 {
		t.Errorf("empty input should have entropy 0, got %.4f", h)
	}
}

func TestShannonEntropy_SingleByte(t *testing.T) {
	// All bytes the same → entropy = 0
	h := content.ShannonEntropy([]byte{0xAA, 0xAA, 0xAA, 0xAA})
	if h != 0 {
		t.Errorf("uniform data should have entropy 0, got %.4f", h)
	}
}

func TestShannonEntropy_TwoBytesEqual(t *testing.T) {
	// Two equally likely symbols → entropy = 1.0
	data := make([]byte, 256)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0x00
		} else {
			data[i] = 0xFF
		}
	}
	h := content.ShannonEntropy(data)
	if math.Abs(h-1.0) > 0.01 {
		t.Errorf("two equiprobable bytes should have entropy ~1.0, got %.4f", h)
	}
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
	// All 256 byte values equally likely → entropy ~ 8.0
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	h := content.ShannonEntropy(data)
	if math.Abs(h-8.0) > 0.01 {
		t.Errorf("uniform distribution over all 256 bytes should give ~8.0 entropy, got %.4f", h)
	}
}

func TestShannonEntropy_PlainText(t *testing.T) {
	// English prose has relatively low entropy (~ 4.0-5.0)
	text := []byte("The quick brown fox jumps over the lazy dog. " +
		"Pack my box with five dozen liquor jugs.")
	h := content.ShannonEntropy(text)
	if h > 6.0 {
		t.Errorf("natural language should have entropy < 6.0, got %.4f", h)
	}
	if h < 3.0 {
		t.Errorf("natural language should have entropy > 3.0, got %.4f", h)
	}
}

func TestShannonEntropy_RandomLike(t *testing.T) {
	// 256 unique consecutive bytes — maximum entropy
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	h := content.ShannonEntropy(data)
	if h < 7.9 {
		t.Errorf("random-like data should have very high entropy, got %.4f", h)
	}
}

// ── AnalyseEntropy levels ─────────────────────────────────────────────────

func TestAnalyseEntropy_Clean(t *testing.T) {
	text := []byte(strings.Repeat("hello world this is normal text ", 10))
	result := content.AnalyseEntropy(text)
	if result.Suspicious {
		t.Errorf("normal text should not be suspicious (score=%.4f)", result.Score)
	}
	if result.Level != "CLEAN" && result.Level != "MEDIUM_ENTROPY" {
		t.Errorf("expected CLEAN or MEDIUM_ENTROPY, got %s", result.Level)
	}
}

func TestAnalyseEntropy_MediumEntropy(t *testing.T) {
	// A JSON document with varied keys/values typically lands around 5-6 bits
	data := []byte(`{"user":"alice","role":"admin","token":"eyJhbGciOiJIUzI1NiJ9","ts":1700000000}`)
	result := content.AnalyseEntropy(data)
	// This might be CLEAN or MEDIUM_ENTROPY — just check Suspicious is reasonable
	if result.Score < 3.0 {
		t.Errorf("JSON payload should have entropy > 3.0, got %.4f", result.Score)
	}
}

func TestAnalyseEntropy_HighEntropySuspicious(t *testing.T) {
	// AES-encrypted or random data — all 256 byte values
	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}
	result := content.AnalyseEntropy(data)
	if !result.Suspicious {
		t.Errorf("near-random data should be flagged suspicious (score=%.4f)", result.Score)
	}
	if result.Level == "CLEAN" {
		t.Errorf("expected HIGH_ENTROPY level, got CLEAN")
	}
}

func TestAnalyseEntropy_VeryHighEntropy(t *testing.T) {
	// Pseudorandom bytes cycling all 256 values
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte((i * 31) % 256) // spread across all values
	}
	result := content.AnalyseEntropy(data)
	if !result.Suspicious {
		t.Errorf("very high entropy data should be Suspicious=true (score=%.4f)", result.Score)
	}
}

func TestAnalyseEntropy_ScoreRounded(t *testing.T) {
	data := []byte("abcdefghij")
	result := content.AnalyseEntropy(data)
	// Score should be rounded to 4 decimal places
	rounded := math.Round(result.Score*10000) / 10000
	if result.Score != rounded {
		t.Errorf("Score should be rounded to 4 decimal places, got %v", result.Score)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkShannonEntropy_1KB(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.ShannonEntropy(data)
	}
}

func BenchmarkAnalyseEntropy_8KB(b *testing.B) {
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.AnalyseEntropy(data)
	}
}
