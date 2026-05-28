package tier3

const (
	BlockThreshold      = 0.85
	SuspiciousThreshold = 0.60
)

// Result holds the anomaly score and action recommendation.
type Result struct {
	Score    float64
	Action   string // "PERMIT" | "SUSPICIOUS" | "BLOCK"
	Features Features
	Reason   string
}

// Features is the fixed-length feature vector fed into the model.
type Features struct {
	MethodEncoded    float64
	URILength        float64
	QueryLength      float64
	HeaderCount      float64
	BodyLength       float64
	URIEntropy       float64
	QueryEntropy     float64
	BodyEntropy      float64
	SpecialCharRatio float64
	EncodedCharCount float64
	DoubleEncoded    float64
	NullBytes        float64
	UnicodeEscape    float64
	HasBase64Body    float64
	ParamCount       float64
	ExcessiveParams  float64
	UALength         float64
	UAIsScanner      float64
	UAEmpty          float64
	UASuspicious     float64
	UnusualMethod    float64
	HasProxyHeaders  float64
}

// scorerImpl is the interface that both heuristic and ONNX backends satisfy.
type scorerImpl interface {
	score(method, uri, query, body, userAgent, contentType string,
		headers map[string]string) Result
}

// Scorer runs anomaly scoring via the available backend.
type Scorer struct {
	impl      scorerImpl
	Threshold float64
}

// NewScorer creates a Scorer with the given block threshold.
func NewScorer(threshold float64) *Scorer {
	return &Scorer{
		impl:      newScorerImpl(threshold),
		Threshold: threshold,
	}
}

// Score computes an anomaly score and returns a Result.
func (s *Scorer) Score(method, uri, query, body, userAgent, contentType string,
	headers map[string]string) Result {
	return s.impl.score(method, uri, query, body, userAgent, contentType, headers)
}
