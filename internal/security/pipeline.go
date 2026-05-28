// Package security orchestrates the 3-tier security pipeline.
package security

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog/log"

	"github.com/aiss/agent/internal/security/content"
	"github.com/aiss/agent/internal/security/tier1"
	"github.com/aiss/agent/internal/security/tier2"
	"github.com/aiss/agent/internal/security/tier3"
	"github.com/aiss/agent/internal/socket"
)

// Verdict is the final security decision for a request.
type Verdict struct {
	Action    string  // "PERMIT" | "BLOCK"
	Tier      int     // 0=cache/static, 1=pattern, 2=injection, 3=ml, 4=content
	CVEID     string
	RuleName  string
	Reason    string
	MLScore   float64
	LatencyMs float64
}

// DBStore is the interface the pipeline needs from the database layer.
type DBStore interface {
	GetIPVerdict(ip string) (verdict, reason string, found bool)
	SetIPVerdict(ip, verdict, reason, cveID string, ttlSec int)
	GetFileHash(sha256 string) (verdict, threatName string, found bool)
	StoreFileHash(sha256, verdict, threatName string)
}

// TelemetrySink receives non-blocking event notifications.
type TelemetrySink interface {
	Send(event map[string]interface{}) bool
}

// Pipeline is the main security check orchestrator. Instantiate once per agent.
type Pipeline struct {
	cfg         pipelineConfig
	tier1Engine *tier1.Engine
	tier3Scorer *tier3.Scorer
	yaraEngine  *content.YARAEngine
	db          DBStore
	telemetry   TelemetrySink
	mode        string // "enforce" | "shadow"
}

type pipelineConfig struct {
	mode             string
	mlThreshold      float64
	fullScanLimit    int
	sampleScanLimit  int
	verdictCacheTTL  int
	patternsFile     string
	rulesDir         string
}

// NewPipeline creates and initialises the pipeline.
func NewPipeline(
	mode string,
	mlThreshold float64,
	patternsFile, rulesDir string,
	fullScanLimit, sampleScanLimit, verdictCacheTTL int,
	db DBStore,
	tel TelemetrySink,
) (*Pipeline, error) {
	t1, err := tier1.NewEngine(patternsFile)
	if err != nil {
		return nil, fmt.Errorf("tier1 init: %w", err)
	}

	yara, err := content.NewYARAEngine(rulesDir)
	if err != nil {
		log.Warn().Err(err).Msg("YARA engine init failed — content scanning degraded")
		yara = &content.YARAEngine{}
	}

	p := &Pipeline{
		cfg: pipelineConfig{
			mode:            mode,
			mlThreshold:     mlThreshold,
			fullScanLimit:   fullScanLimit,
			sampleScanLimit: sampleScanLimit,
			verdictCacheTTL: verdictCacheTTL,
			patternsFile:    patternsFile,
			rulesDir:        rulesDir,
		},
		tier1Engine: t1,
		tier3Scorer: tier3.NewScorer(mlThreshold),
		yaraEngine:  yara,
		db:          db,
		telemetry:   tel,
		mode:        mode,
	}

	log.Info().
		Str("mode", mode).
		Int("cve_patterns", t1.PatternCount()).
		Int("yara_rules", yara.RuleCount()).
		Float64("ml_threshold", mlThreshold).
		Msg("Security pipeline initialised")

	return p, nil
}

// Check runs the full 3-tier pipeline against a request.
// This is the hot path — every millisecond counts.
func (p *Pipeline) Check(req *socket.Request) *socket.Response {
	t0 := time.Now()

	// ── Pre-filter: static files bypass the pipeline ─────────────────────
	if isStaticFile(req.URI) {
		return p.permit(0, "static file — skipped", 0, t0)
	}

	// ── Verdict cache: known IPs bypass the pipeline ─────────────────────
	if p.db != nil {
		if verdict, reason, found := p.db.GetIPVerdict(req.ClientIP); found {
			if verdict == "BLOCK" {
				return p.block(0, "CACHED-BLOCK", "", reason, 0, t0, req)
			}
			return p.permit(0, "cached permit: "+reason, 0, t0)
		}
	}

	// ── Build unified scan string ─────────────────────────────────────────
	scanData := buildScanData(req)

	// ── Tier 1: CVE Pattern Matching ─────────────────────────────────────
	t1Result := p.tier1Engine.Scan(scanData)
	if t1Result.Matched {
		if p.db != nil {
			p.db.SetIPVerdict(req.ClientIP, "BLOCK",
				"CVE: "+t1Result.CVEID, t1Result.CVEID, p.cfg.verdictCacheTTL)
		}
		return p.block(1, t1Result.CVEID, "",
			"CVE pattern match: "+t1Result.Name+" — "+t1Result.Description,
			0, t0, req)
	}

	// ── Tier 2: SQLi / XSS ───────────────────────────────────────────────
	inputs := extractInputSlice(req)

	sqli := tier2.CheckSQLi(inputs)
	if sqli.Detected {
		return p.block(2, "GENERIC-SQLI", "", sqli.Detail, 0, t0, req)
	}

	xss := tier2.CheckXSS(inputs)
	if xss.Detected {
		return p.block(2, "GENERIC-XSS", "", xss.Detail, 0, t0, req)
	}

	// ── Content Inspection (Base64 / file uploads) ────────────────────────
	if len(req.Body) > 0 && shouldInspectContent(req.ContentType) {
		if v := p.inspectContent(req, t0); v != nil {
			return v
		}
	}

	// ── Tier 3: ML Anomaly Detection ─────────────────────────────────────
	body := string(req.Body)
	if !utf8.ValidString(body) {
		body = ""
	}
	mlResult := p.tier3Scorer.Score(
		req.Method, req.URI, req.QueryString, body,
		req.UserAgent, req.ContentType, req.Headers,
	)
	if mlResult.Action == "BLOCK" {
		return p.block(3, "", "",
			fmt.Sprintf("ML anomaly score %.3f ≥ %.2f: %s",
				mlResult.Score, p.cfg.mlThreshold, mlResult.Reason),
			mlResult.Score, t0, req)
	}

	// ── All checks passed ────────────────────────────────────────────────
	if p.db != nil {
		p.db.SetIPVerdict(req.ClientIP, "PERMIT", "all checks passed", "", p.cfg.verdictCacheTTL)
	}
	resp := p.permit(0, "all security checks passed", mlResult.Score, t0)
	p.emitTelemetry(req, resp)
	return resp
}

// ReloadRules hot-reloads CVE patterns and YARA rules without restart.
func (p *Pipeline) ReloadRules() {
	if err := p.tier1Engine.Load(p.cfg.patternsFile); err != nil {
		log.Error().Err(err).Msg("CVE pattern reload failed")
	}
	if err := p.yaraEngine.Load(p.cfg.rulesDir); err != nil {
		log.Error().Err(err).Msg("YARA rule reload failed")
	}
	log.Info().Msg("Rules hot-reloaded")
}

// ── Content Inspection ────────────────────────────────────────────────────

func (p *Pipeline) inspectContent(req *socket.Request, t0 time.Time) *socket.Response {
	size := len(req.Body)

	var targets [][]byte
	switch {
	case size <= p.cfg.fullScanLimit:
		targets = p.fullScanTargets(req.Body, req.ContentType)
	case size <= p.cfg.sampleScanLimit:
		targets = sampledTargets(req.Body)
	default:
		// Large payload — async inspection, pass inline
		go p.asyncScan(req.Body)
		return nil
	}

	for _, target := range targets {
		if len(target) == 0 {
			continue
		}

		// SHA-256 hash dedup
		hash := sha256Hex(target)
		if p.db != nil {
			if verdict, threat, found := p.db.GetFileHash(hash); found {
				if verdict == "MALICIOUS" {
					return p.block(4, "", threat,
						fmt.Sprintf("Known malicious content (SHA-256: %.16s...)", hash),
						0, t0, req)
				}
				return nil // known clean
			}
		}

		// Magic byte check
		magic := content.ValidateMagicBytes(target, req.ContentType)
		if magic.ShouldBlock {
			p.cacheFileHash(hash, "MALICIOUS", magic.DetectedKey)
			return p.block(4, "", magic.DetectedKey, magic.Reason, 0, t0, req)
		}

		// YARA scan
		yaraResult := p.yaraEngine.Scan(target)
		if yaraResult.Matched {
			p.cacheFileHash(hash, "MALICIOUS", yaraResult.RuleName)
			return p.block(4, "", yaraResult.RuleName,
				fmt.Sprintf("YARA: %s — %s", yaraResult.RuleName, yaraResult.Description),
				0, t0, req)
		}

		// Entropy check (suspicious only — combine with other signals)
		ent := content.AnalyseEntropy(target)
		if ent.Suspicious && yaraResult.Matched {
			p.cacheFileHash(hash, "MALICIOUS", "high_entropy+yara")
			return p.block(4, "", "high_entropy",
				fmt.Sprintf("High-entropy payload (%.2f) with YARA hit", ent.Score),
				0, t0, req)
		}

		// Cache as clean
		p.cacheFileHash(hash, "CLEAN", "")
	}
	return nil
}

func (p *Pipeline) fullScanTargets(body []byte, ct string) [][]byte {
	targets := [][]byte{body}
	if decoded := content.DecodeIfBase64(body, ct); decoded != nil {
		targets = append(targets, decoded)
	}
	for _, cand := range content.ExtractB64Candidates(body) {
		targets = append(targets, cand)
	}
	return targets
}

func sampledTargets(body []byte) [][]byte {
	n := len(body)
	mid := n / 2
	head := body[:min(4096, n)]
	tail := body[max(0, n-4096):]
	midSlice := body[max(0, mid-2048):min(n, mid+2048)]
	return [][]byte{head, midSlice, tail}
}

func (p *Pipeline) asyncScan(body []byte) {
	result := p.yaraEngine.Scan(body)
	if result.Matched {
		log.Warn().
			Str("rule", result.RuleName).
			Int("size", len(body)).
			Msg("Async scan: malicious content detected in large payload (session not killable)")
	}
}

func (p *Pipeline) cacheFileHash(hash, verdict, threat string) {
	if p.db != nil {
		p.db.StoreFileHash(hash, verdict, threat)
	}
}

// ── Response builders ─────────────────────────────────────────────────────

func (p *Pipeline) block(tier int, cveID, ruleName, reason string, mlScore float64, t0 time.Time, req *socket.Request) *socket.Response {
	action := "BLOCK"
	if p.mode == "shadow" {
		action = "PERMIT"
		reason = "[SHADOW] Would block: " + reason
	}
	resp := &socket.Response{
		Action:  action,
		Tier:    tier,
		CVEID:   cveID,
		RuleName: ruleName,
		Reason:  reason,
		MLScore: mlScore,
	}
	p.emitTelemetry(req, resp)
	log.Info().
		Str("action", action).
		Str("ip", req.ClientIP).
		Str("uri", req.URI).
		Int("tier", tier).
		Str("reason", reason).
		Msg("security verdict")
	return resp
}

func (p *Pipeline) permit(tier int, reason string, mlScore float64, t0 time.Time) *socket.Response {
	return &socket.Response{
		Action:  "PERMIT",
		Tier:    tier,
		Reason:  reason,
		MLScore: mlScore,
	}
}

func (p *Pipeline) emitTelemetry(req *socket.Request, resp *socket.Response) {
	if p.telemetry == nil {
		return
	}
	p.telemetry.Send(map[string]interface{}{
		"request_id": req.RequestID,
		"client_ip":  req.ClientIP,
		"method":     req.Method,
		"uri":        req.URI,
		"action":     resp.Action,
		"tier":       resp.Tier,
		"cve_id":     resp.CVEID,
		"rule_name":  resp.RuleName,
		"reason":     resp.Reason,
		"ml_score":   resp.MLScore,
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────

var staticExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".webp": true, ".svg": true, ".ico": true,
	".css": true, ".js": true, ".mjs": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".wav": true,
}

func isStaticFile(uri string) bool {
	path := strings.SplitN(uri, "?", 2)[0]
	dot := strings.LastIndex(path, ".")
	if dot < 0 {
		return false
	}
	return staticExtensions[strings.ToLower(path[dot:])]
}

func shouldInspectContent(ct string) bool {
	ct = strings.ToLower(ct)
	for _, t := range []string{
		"application/x-www-form-urlencoded",
		"application/json",
		"application/xml",
		"text/xml",
		"text/plain",
		"application/octet-stream",
		"multipart/form-data",
	} {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

func buildScanData(req *socket.Request) string {
	var sb strings.Builder
	sb.WriteString(req.URI)
	sb.WriteByte(' ')
	sb.WriteString(req.QueryString)
	sb.WriteByte(' ')
	sb.WriteString(req.UserAgent)
	sb.WriteByte(' ')
	if v, ok := req.Headers["referer"]; ok {
		sb.WriteString(v)
	}
	sb.WriteByte(' ')
	if v, ok := req.Headers["cookie"]; ok {
		sb.WriteString(v)
	}
	if len(req.Body) > 0 {
		sb.WriteByte(' ')
		body := req.Body
		if len(body) > 4096 {
			body = body[:4096]
		}
		sb.Write(body)
	}
	return sb.String()
}

func extractInputSlice(req *socket.Request) []string {
	inputs := []string{req.URI, req.QueryString}
	for _, h := range []string{"user-agent", "referer", "cookie", "x-forwarded-for"} {
		if v, ok := req.Headers[h]; ok && v != "" {
			inputs = append(inputs, v)
		}
	}
	if len(req.Body) > 0 {
		inputs = append(inputs, string(req.Body))
	}
	return inputs
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
