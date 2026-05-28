//go:build !onnx

// Package tier3 implements ML-based anomaly detection.
// Production equivalent: ONNX Runtime with a Random Forest model.
// This implements the same feature extraction and scoring heuristic
// that the trained model would approximate, ready to swap with ONNX.
package tier3

// newScorerImpl returns the heuristic scorer (used when the onnx build tag is absent).
// The heuristicScorer type and all scoring logic live in scorer_helpers.go.
func newScorerImpl(threshold float64) scorerImpl {
	return &heuristicScorer{Threshold: threshold}
}
