//go:build onnx

package tier3

import (
	"fmt"
	"os"
	"path/filepath"

	ort "github.com/yalue/onnxruntime_go"
	"github.com/rs/zerolog/log"
)

const onnxModelEnv = "AISS_ONNX_MODEL"
const onnxModelDefault = "/etc/aiss/ml/aiss_model.onnx"

type onnxScorer struct {
	session   *ort.AdvancedSession
	threshold float64
	// Fallback to heuristic if model not available
	fallback *heuristicScorer
}

func newScorerImpl(threshold float64) scorerImpl {
	modelPath := os.Getenv(onnxModelEnv)
	if modelPath == "" {
		modelPath = onnxModelDefault
	}
	modelPath, _ = filepath.Abs(modelPath)

	if _, err := os.Stat(modelPath); err != nil {
		log.Warn().Str("path", modelPath).
			Msg("ONNX model not found — falling back to heuristic scorer")
		return &heuristicScorer{Threshold: threshold}
	}

	if err := ort.InitializeEnvironment(); err != nil {
		log.Warn().Err(err).Msg("ONNX Runtime init failed — falling back to heuristic scorer")
		return &heuristicScorer{Threshold: threshold}
	}

	// Input: [1, 22] float32 features
	inputShape := ort.NewShape(1, 22)
	outputShape := ort.NewShape(1, 1)

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"features"},
		[]string{"score"},
		[]ort.ArbitraryTensor{
			func() ort.ArbitraryTensor {
				t, _ := ort.NewEmptyTensor[float32](inputShape)
				return t
			}(),
		},
		[]ort.ArbitraryTensor{
			func() ort.ArbitraryTensor {
				t, _ := ort.NewEmptyTensor[float32](outputShape)
				return t
			}(),
		},
		nil,
	)
	if err != nil {
		log.Warn().Err(err).Str("model", modelPath).
			Msg("ONNX session creation failed — falling back to heuristic scorer")
		return &heuristicScorer{Threshold: threshold}
	}

	log.Info().Str("model", modelPath).Msg("ONNX model loaded for tier3 ML scoring")
	return &onnxScorer{
		session:   session,
		threshold: threshold,
		fallback:  &heuristicScorer{Threshold: threshold},
	}
}

func (s *onnxScorer) score(method, uri, query, body, userAgent, contentType string,
	headers map[string]string) Result {

	// Extract the same 22 features used by the heuristic scorer
	f := extractFeatures(method, uri, query, body, userAgent, contentType, headers)
	featureVec := featureVector(f)

	inputShape := ort.NewShape(1, 22)
	inputTensor, err := ort.NewTensor(inputShape, featureVec)
	if err != nil {
		return s.fallback.score(method, uri, query, body, userAgent, contentType, headers)
	}
	defer inputTensor.Destroy()

	outputShape := ort.NewShape(1, 1)
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return s.fallback.score(method, uri, query, body, userAgent, contentType, headers)
	}
	defer outputTensor.Destroy()

	if err := s.session.Run(); err != nil {
		log.Debug().Err(err).Msg("ONNX inference error — using heuristic fallback")
		return s.fallback.score(method, uri, query, body, userAgent, contentType, headers)
	}

	data := outputTensor.GetData()
	if len(data) == 0 {
		return s.fallback.score(method, uri, query, body, userAgent, contentType, headers)
	}

	rawScore := float64(data[0])
	action := "PERMIT"
	reason := fmt.Sprintf("ONNX score %.4f", rawScore)
	if rawScore >= s.threshold {
		action = "BLOCK"
		reason = fmt.Sprintf("ONNX anomaly score %.4f >= threshold %.2f", rawScore, s.threshold)
	} else if rawScore >= SuspiciousThreshold {
		action = "SUSPICIOUS"
	}

	return Result{
		Score:    roundTo(rawScore, 4),
		Action:   action,
		Features: f,
		Reason:   reason,
	}
}

// featureVector converts the Features struct into a []float32 slice.
// Order MUST match the model training feature order in scripts/train_model.py.
func featureVector(f Features) []float32 {
	return []float32{
		float32(f.MethodEncoded),
		float32(f.URILength),
		float32(f.QueryLength),
		float32(f.HeaderCount),
		float32(f.BodyLength),
		float32(f.URIEntropy),
		float32(f.QueryEntropy),
		float32(f.BodyEntropy),
		float32(f.SpecialCharRatio),
		float32(f.EncodedCharCount),
		float32(f.DoubleEncoded),
		float32(f.NullBytes),
		float32(f.UnicodeEscape),
		float32(f.HasBase64Body),
		float32(f.ParamCount),
		float32(f.ExcessiveParams),
		float32(f.UALength),
		float32(f.UAIsScanner),
		float32(f.UAEmpty),
		float32(f.UASuspicious),
		float32(f.UnusualMethod),
		float32(f.HasProxyHeaders),
	}
}
