package content

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// minB64Length is the minimum Base64 string length worth decoding (36 raw bytes).
const minB64Length = 48

var b64Pattern = regexp.MustCompile(
	`(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})`)

// ExtractB64Candidates finds and decodes all Base64 substrings in a payload.
func ExtractB64Candidates(data []byte) [][]byte {
	text := string(data)
	var decoded [][]byte
	for _, match := range b64Pattern.FindAllString(text, -1) {
		if len(match) < minB64Length {
			continue
		}
		// Ensure proper padding
		padded := match
		if mod := len(padded) % 4; mod != 0 {
			padded += strings.Repeat("=", 4-mod)
		}
		raw, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			continue
		}
		if len(raw) >= 16 {
			decoded = append(decoded, raw)
		}
	}
	return decoded
}

// DecodeIfBase64 attempts to decode the entire body as Base64.
// Returns nil if the body does not appear to be Base64.
func DecodeIfBase64(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "multipart") || strings.Contains(ct, "text/html") {
		return nil
	}

	// Strip whitespace
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(body))

	// Add padding if needed
	padded := clean
	if mod := len(padded) % 4; mod != 0 {
		padded += strings.Repeat("=", 4-mod)
	}

	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return nil
	}
	// Sanity: decoded should be meaningfully shorter than encoded
	if float64(len(decoded)) >= float64(len(body))*0.75 {
		return nil
	}
	return decoded
}
