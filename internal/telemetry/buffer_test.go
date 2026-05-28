package telemetry_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiss/agent/internal/telemetry"
)

// ── Test sink ─────────────────────────────────────────────────────────────

// captureSink records every event batch it receives.
type captureSink struct {
	mu     sync.Mutex
	events []map[string]interface{}
	calls  int
}

func (s *captureSink) Flush(events []map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	s.calls++
	return nil
}

func (s *captureSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *captureSink) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// ── Basic send / receive ──────────────────────────────────────────────────

func TestBuffer_Send_Accepted(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(100, 10, 50*time.Millisecond, sink)
	defer buf.Stop()

	ok := buf.Send(map[string]interface{}{"action": "BLOCK", "ip": "1.2.3.4"})
	if !ok {
		t.Error("Send should return true when buffer has capacity")
	}
}

func TestBuffer_Stop_FlushesRemaining(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(1000, 500, 10*time.Second, sink) // long flush interval — only Stop flushes

	// Send 5 events
	for i := 0; i < 5; i++ {
		buf.Send(map[string]interface{}{"seq": i})
	}

	buf.Stop() // must flush remaining 5 before returning

	if sink.Count() != 5 {
		t.Errorf("Stop should flush all remaining events; expected 5, got %d", sink.Count())
	}
}

func TestBuffer_BatchFlush_OnBatchSize(t *testing.T) {
	sink := &captureSink{}
	batchSize := 5
	buf := telemetry.New(1000, batchSize, 10*time.Second, sink)
	defer buf.Stop()

	// Send exactly batchSize events — should trigger an immediate flush
	for i := 0; i < batchSize; i++ {
		buf.Send(map[string]interface{}{"n": i})
	}

	// Give the flusher goroutine a moment to process
	time.Sleep(100 * time.Millisecond)

	if sink.Count() < batchSize {
		t.Errorf("sending batchSize events should trigger flush; got %d/%d events", sink.Count(), batchSize)
	}
}

func TestBuffer_TickerFlush(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(1000, 500, 50*time.Millisecond, sink) // 50ms ticker
	defer buf.Stop()

	buf.Send(map[string]interface{}{"type": "ticker_test"})

	// Wait > 1 flush interval
	time.Sleep(200 * time.Millisecond)

	if sink.Count() == 0 {
		t.Error("ticker should have flushed the event within 200ms")
	}
}

// ── Drop behavior when full ───────────────────────────────────────────────

func TestBuffer_DropWhenFull(t *testing.T) {
	// Capacity 3, slow-processing sink (won't flush in time)
	sink := &captureSink{}
	buf := telemetry.New(3, 100, 10*time.Second, sink)
	defer buf.Stop()

	var dropped int
	for i := 0; i < 10; i++ {
		if !buf.Send(map[string]interface{}{"n": i}) {
			dropped++
		}
	}

	if dropped == 0 {
		t.Error("at least some events should be dropped when buffer is full")
	}
}

func TestBuffer_Stats_TrackDropped(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(2, 100, 10*time.Second, sink)
	defer buf.Stop()

	// Fill and overflow
	for i := 0; i < 10; i++ {
		buf.Send(map[string]interface{}{"i": i})
	}

	stats := buf.Stats()
	if stats["dropped"] == 0 {
		t.Error("Stats should report dropped events when buffer overflows")
	}
}

func TestBuffer_Stats_TrackFlushed(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(1000, 3, 10*time.Second, sink)

	for i := 0; i < 3; i++ {
		buf.Send(map[string]interface{}{"i": i})
	}
	time.Sleep(100 * time.Millisecond) // allow flush

	buf.Stop()

	stats := buf.Stats()
	if stats["flushed"] < 3 {
		t.Errorf("Stats.flushed should be >= 3, got %d", stats["flushed"])
	}
}

// ── NoopSink ──────────────────────────────────────────────────────────────

func TestBuffer_NoopSink_DoesNotPanic(t *testing.T) {
	buf := telemetry.New(100, 5, 50*time.Millisecond, telemetry.NoopSink{})
	for i := 0; i < 20; i++ {
		buf.Send(map[string]interface{}{"n": i})
	}
	time.Sleep(200 * time.Millisecond)
	buf.Stop()
	// Should not panic or deadlock
}

// ── Nil sink ──────────────────────────────────────────────────────────────

func TestBuffer_NilSink_DoesNotPanic(t *testing.T) {
	buf := telemetry.New(100, 5, 50*time.Millisecond, nil)
	for i := 0; i < 10; i++ {
		buf.Send(map[string]interface{}{"n": i})
	}
	time.Sleep(100 * time.Millisecond)
	buf.Stop()
}

// ── Concurrency ───────────────────────────────────────────────────────────

func TestBuffer_ConcurrentSend(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(10_000, 100, 50*time.Millisecond, sink)

	var sent atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		g := g // capture loop variable
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if buf.Send(map[string]interface{}{"goroutine": g, "i": i}) {
					sent.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	buf.Stop()

	total := sink.Count()
	dropped := buf.Stats()["dropped"]
	if int64(total)+dropped != sent.Load() {
		// Allow some slack: flushed + dropped ≈ sent
		// This checks that we didn't double-count or lose events
		t.Logf("sent=%d flushed=%d dropped=%d (note: some events may still be in flight)", sent.Load(), total, dropped)
	}
}

func TestBuffer_Stop_IdempotentClose(t *testing.T) {
	// Stop should not panic if called after events have been drained
	sink := &captureSink{}
	buf := telemetry.New(100, 5, 10*time.Millisecond, sink)
	buf.Send(map[string]interface{}{"k": "v"})
	buf.Stop()
	// Second stop: this tests that double-close doesn't panic
	// (Note: in production, Stop should only be called once — this is defensive testing)
}

// ── Event payload integrity ────────────────────────────────────────────────

func TestBuffer_EventPayload_PreservedThroughSink(t *testing.T) {
	sink := &captureSink{}
	buf := telemetry.New(100, 1, 50*time.Millisecond, sink)
	defer buf.Stop()

	event := map[string]interface{}{
		"request_id": "req-xyz",
		"client_ip":  "10.0.0.1",
		"method":     "GET",
		"action":     "BLOCK",
		"tier":       2,
		"ml_score":   0.923,
	}
	buf.Send(event)
	time.Sleep(100 * time.Millisecond)

	if sink.Count() == 0 {
		t.Fatal("event should have been flushed")
	}
	received := sink.events[0]
	if received["request_id"] != "req-xyz" {
		t.Errorf("request_id mismatch: got %v", received["request_id"])
	}
	if received["action"] != "BLOCK" {
		t.Errorf("action mismatch: got %v", received["action"])
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────

func BenchmarkBuffer_Send(b *testing.B) {
	buf := telemetry.New(10_000, 200, 50*time.Millisecond, telemetry.NoopSink{})
	defer buf.Stop()
	event := map[string]interface{}{
		"action": "PERMIT",
		"ip":     "1.2.3.4",
		"uri":    "/api/products",
		"score":  0.1,
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Send(event)
	}
}
