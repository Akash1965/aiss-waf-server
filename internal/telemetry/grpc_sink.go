// Package telemetry — gRPC sink that forwards batched events to the central server.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	aissv1 "github.com/aiss/agent/proto/gen/go"
)

// GRPCSink sends telemetry to the central server via its /v1/telemetry HTTP
// endpoint (JSON-over-HTTP fallback until the full gRPC transport is wired up).
// The interface is identical to the true gRPC sink so the swap is transparent.
type GRPCSink struct {
	serverURL string
	agentID   string
	apiKey    string
	client    *http.Client
}

// NewGRPCSink creates a GRPCSink that posts to serverURL/v1/telemetry.
func NewGRPCSink(serverURL, agentID, apiKey string) *GRPCSink {
	return &GRPCSink{
		serverURL: serverURL,
		agentID:   agentID,
		apiKey:    apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: false,
			},
		},
	}
}

// Flush implements Sink. It converts the raw event maps into TelemetryBatch
// and POSTs them to the server.
func (s *GRPCSink) Flush(events []map[string]interface{}) error {
	if len(events) == 0 {
		return nil
	}

	batch := &aissv1.TelemetryBatch{
		Events: make([]*aissv1.TelemetryEvent, 0, len(events)),
	}

	now := time.Now().UnixMilli()
	for _, ev := range events {
		e := &aissv1.TelemetryEvent{
			AgentID:    s.agentID,
			Timestamp:  now,
			RequestID:  strVal(ev, "request_id"),
			ClientIP:   strVal(ev, "client_ip"),
			Method:     strVal(ev, "method"),
			URI:        strVal(ev, "uri"),
			Action:     strVal(ev, "action"),
			Tier:       int32(intVal(ev, "tier")),
			CVEID:      strVal(ev, "cve_id"),
			RuleName:   strVal(ev, "rule_name"),
			Reason:     strVal(ev, "reason"),
			MLScore:    floatVal(ev, "ml_score"),
			LatencyMs:  floatVal(ev, "latency_ms"),
			ServerType: strVal(ev, "server_type"),
		}
		batch.Events = append(batch.Events, e)
	}

	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal telemetry batch: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.serverURL+"/v1/telemetry", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build telemetry request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telemetry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("telemetry server returned %d", resp.StatusCode)
	}

	log.Debug().Int("events", len(events)).Msg("Telemetry batch sent")
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intVal(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case int:
			return t
		case int32:
			return int(t)
		case int64:
			return int(t)
		case float64:
			return int(t)
		}
	}
	return 0
}

func floatVal(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return math.Round(f*10000) / 10000
		}
	}
	return 0
}
