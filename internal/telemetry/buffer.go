// Package telemetry provides a non-blocking ring buffer for security events.
// The security pipeline never waits on telemetry — if the buffer is full, events are dropped.
package telemetry

import (
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Sink receives batched telemetry events.
type Sink interface {
	Flush(events []map[string]interface{}) error
}

// DBSink stores events in the local database.
type DBSink interface {
	StoreEvent(e interface{})
}

// Buffer is a lock-free ring buffer backed by a Go channel.
type Buffer struct {
	ch            chan map[string]interface{}
	sink          Sink
	batchSize     int
	flushInterval time.Duration
	quit          chan struct{}
	done          chan struct{}

	dropped atomic.Int64
	flushed atomic.Int64
}

// New creates and starts a Buffer.
func New(capacity, batchSize int, flushInterval time.Duration, sink Sink) *Buffer {
	b := &Buffer{
		ch:            make(chan map[string]interface{}, capacity),
		sink:          sink,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		quit:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	go b.run()
	log.Info().
		Int("capacity", capacity).
		Int("batch", batchSize).
		Dur("interval", flushInterval).
		Msg("Telemetry buffer started")
	return b
}

// Send submits an event non-blocking. Returns false if dropped.
func (b *Buffer) Send(event map[string]interface{}) bool {
	select {
	case b.ch <- event:
		return true
	default:
		dropped := b.dropped.Add(1)
		if dropped%500 == 1 {
			log.Warn().Int64("total_dropped", dropped).Msg("Telemetry buffer full — events dropped")
		}
		return false
	}
}

// Stop flushes remaining events and shuts down the flusher goroutine.
func (b *Buffer) Stop() {
	close(b.quit)
	<-b.done
}

// Stats returns current counters.
func (b *Buffer) Stats() map[string]int64 {
	return map[string]int64{
		"queued":  int64(len(b.ch)),
		"flushed": b.flushed.Load(),
		"dropped": b.dropped.Load(),
	}
}

func (b *Buffer) run() {
	defer close(b.done)
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	batch := make([]map[string]interface{}, 0, b.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if b.sink != nil {
			if err := b.sink.Flush(batch); err != nil {
				log.Debug().Err(err).Msg("Telemetry flush error")
			}
		}
		b.flushed.Add(int64(len(batch)))
		batch = batch[:0]
	}

	for {
		select {
		case event := <-b.ch:
			batch = append(batch, event)
			if len(batch) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.quit:
			// Drain remaining
			for len(b.ch) > 0 {
				batch = append(batch, <-b.ch)
			}
			flush()
			return
		}
	}
}

// NoopSink discards all events (useful in tests or when server is unreachable).
type NoopSink struct{}

func (NoopSink) Flush(_ []map[string]interface{}) error { return nil }
