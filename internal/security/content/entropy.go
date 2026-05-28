// Package content provides content inspection: entropy, magic bytes, Base64 decoding.
package content

import (
	"math"
)

const (
	EntropyHighThreshold = 7.2 // above = suspicious (encrypted/packed)
	EntropyVeryHigh      = 7.8 // above = likely encrypted
)

// EntropyResult describes the entropy analysis of a byte slice.
type EntropyResult struct {
	Score      float64
	Suspicious bool
	Level      string
}

// ShannonEntropy computes the Shannon entropy of binary data (0.0–8.0).
// Values above 7.0 strongly suggest encryption, compression, or packing.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// AnalyseEntropy runs entropy analysis and classifies the result.
func AnalyseEntropy(data []byte) EntropyResult {
	score := ShannonEntropy(data)
	suspicious := score >= EntropyHighThreshold
	level := "CLEAN"
	switch {
	case score >= EntropyVeryHigh:
		level = "HIGH_ENTROPY_LIKELY_ENCRYPTED"
	case score >= EntropyHighThreshold:
		level = "HIGH_ENTROPY_SUSPICIOUS"
	case score >= 6.0:
		level = "MEDIUM_ENTROPY"
	}
	return EntropyResult{Score: math.Round(score*10000) / 10000, Suspicious: suspicious, Level: level}
}
