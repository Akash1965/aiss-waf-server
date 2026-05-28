package content

import "strings"

// MagicSignature defines a known file type by its header bytes.
type MagicSignature struct {
	Key         string
	Magic       []byte
	Description string
	Dangerous   bool
}

// knownSignatures is the ordered table of magic byte prefixes.
var knownSignatures = []MagicSignature{
	// Executables — always dangerous in web uploads
	{Key: "EXE_WINDOWS", Magic: []byte{0x4D, 0x5A}, Description: "Windows PE Executable", Dangerous: true},
	{Key: "ELF_LINUX", Magic: []byte{0x7F, 0x45, 0x4C, 0x46}, Description: "Linux ELF Executable", Dangerous: true},
	{Key: "MACHO", Magic: []byte{0xCE, 0xFA, 0xED, 0xFE}, Description: "macOS Mach-O Binary", Dangerous: true},

	// Scripts — dangerous if disguised as other types
	{Key: "PHP_SCRIPT", Magic: []byte{0x3C, 0x3F, 0x70, 0x68, 0x70}, Description: "PHP Script (<?php)", Dangerous: true},
	{Key: "PHP_SHORT", Magic: []byte{0x3C, 0x3F}, Description: "PHP Short Tag (<?)", Dangerous: true},
	{Key: "SHELL_SHEBANG", Magic: []byte{0x23, 0x21}, Description: "Shell Script (#!)", Dangerous: true},

	// Java
	{Key: "JAVA_CLASS", Magic: []byte{0xCA, 0xFE, 0xBA, 0xBE}, Description: "Java Class File", Dangerous: true},

	// Archives (inspect content but not inherently dangerous by type alone)
	{Key: "ZIP", Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Description: "ZIP / Office Document"},
	{Key: "GZIP", Magic: []byte{0x1F, 0x8B}, Description: "GZIP"},
	{Key: "7ZIP", Magic: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Description: "7-Zip Archive"},
	{Key: "RAR", Magic: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, Description: "RAR Archive"},

	// Documents
	{Key: "PDF", Magic: []byte{0x25, 0x50, 0x44, 0x46}, Description: "PDF Document"},
	{Key: "OLE2", Magic: []byte{0xD0, 0xCF, 0x11, 0xE0}, Description: "MS Office OLE2 (doc/xls/ppt)"},

	// Images (legitimate)
	{Key: "JPEG", Magic: []byte{0xFF, 0xD8, 0xFF}, Description: "JPEG Image"},
	{Key: "PNG", Magic: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, Description: "PNG Image"},
	{Key: "GIF87", Magic: []byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, Description: "GIF87 Image"},
	{Key: "GIF89", Magic: []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, Description: "GIF89 Image"},
}

// contentTypeExpected maps declared Content-Type → expected magic keys.
var contentTypeExpected = map[string][]string{
	"image/jpeg":      {"JPEG"},
	"image/png":       {"PNG"},
	"image/gif":       {"GIF87", "GIF89"},
	"application/pdf": {"PDF"},
	"application/zip": {"ZIP", "7ZIP", "RAR"},
}

// MagicResult is the outcome of a magic byte validation.
type MagicResult struct {
	DetectedKey  string
	Description  string
	IsDangerous  bool
	IsSpoofed    bool
	ShouldBlock  bool
	Reason       string
}

// ValidateMagicBytes detects actual file type and checks for spoofing.
func ValidateMagicBytes(data []byte, declaredContentType string) MagicResult {
	result := MagicResult{}
	if len(data) < 2 {
		return result
	}
	header := data
	if len(header) > 16 {
		header = header[:16]
	}

	// Detect actual type
	var detected *MagicSignature
	for i := range knownSignatures {
		sig := &knownSignatures[i]
		if len(header) >= len(sig.Magic) {
			match := true
			for j, b := range sig.Magic {
				if header[j] != b {
					match = false
					break
				}
			}
			if match {
				detected = sig
				break
			}
		}
	}

	if detected == nil {
		return result
	}

	result.DetectedKey = detected.Key
	result.Description = detected.Description
	result.IsDangerous = detected.Dangerous

	if detected.Dangerous {
		result.ShouldBlock = true
		result.Reason = "Dangerous file type detected: " + detected.Description
		return result
	}

	// Check Content-Type spoofing
	ct := strings.ToLower(strings.Split(declaredContentType, ";")[0])
	ct = strings.TrimSpace(ct)
	if expected, ok := contentTypeExpected[ct]; ok {
		spoofed := true
		for _, k := range expected {
			if k == detected.Key {
				spoofed = false
				break
			}
		}
		if spoofed {
			result.IsSpoofed = true
			result.ShouldBlock = true
			result.Reason = "Content-Type spoofing: claimed '" + ct +
				"' but file is actually " + detected.Description
		}
	}
	return result
}
