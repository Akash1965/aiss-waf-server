// Package socket implements the Unix Domain Socket server that receives
// security check requests from the Nginx/Apache C module.
package socket

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Request is the JSON payload sent by the Nginx/Apache C module.
type Request struct {
	RequestID   string            `json:"request_id"`
	ClientIP    string            `json:"client_ip"`
	Method      string            `json:"method"`
	URI         string            `json:"uri"`
	QueryString string            `json:"query_string"`
	ContentType string            `json:"content_type"`
	ContentLen  int64             `json:"content_length"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body"`      // First 4096 bytes
	UserAgent   string            `json:"user_agent"`
	ServerType  string            `json:"server_type"` // "nginx" | "apache"
}

// Response is sent back to the C module.
type Response struct {
	Action    string  `json:"action"`    // "PERMIT" | "BLOCK"
	Reason    string  `json:"reason"`
	Tier      int     `json:"tier"`
	CVEID     string  `json:"cve_id,omitempty"`
	RuleName  string  `json:"rule_name,omitempty"`
	MLScore   float64 `json:"ml_score"`
	LatencyMs float64 `json:"latency_ms"`
}

// Handler is the function called for each incoming request.
type Handler func(req *Request) *Response

// Server is the Unix Domain Socket listener.
type Server struct {
	socketPath string
	handler    Handler
	timeoutMs  int
	maxWorkers int

	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}

	// Stats (atomic for lock-free reads)
	statTotal    atomic.Int64
	statBlocked  atomic.Int64
	statPermitted atomic.Int64
	statErrors   atomic.Int64
	statFailOpen atomic.Int64
}

// New creates a new UDS server.
func New(socketPath string, handler Handler, timeoutMs, maxWorkers int) *Server {
	return &Server{
		socketPath: socketPath,
		handler:    handler,
		timeoutMs:  timeoutMs,
		maxWorkers: maxWorkers,
		quit:       make(chan struct{}),
	}
}

// Start binds the socket and begins accepting connections.
// Blocks until Stop() is called.
func (s *Server) Start() error {
	// Remove stale socket file
	_ = os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("socket listen on %s: %w", s.socketPath, err)
	}
	// www-data needs access
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	s.listener = ln

	// Bounded worker pool using semaphore channel
	sem := make(chan struct{}, s.maxWorkers)

	log.Info().Str("path", s.socketPath).Int("workers", s.maxWorkers).
		Msg("AISS agent listening on Unix socket")

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				s.wg.Wait()
				return nil
			default:
				log.Error().Err(err).Msg("accept error")
				continue
			}
		}

		sem <- struct{}{} // Acquire worker slot
		s.wg.Add(1)
		go func(c net.Conn) {
			defer func() {
				<-sem
				s.wg.Done()
			}()
			s.handleConn(c)
		}(conn)
	}
}

// Stop shuts down the server gracefully.
func (s *Server) Stop() {
	close(s.quit)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
	_ = os.Remove(s.socketPath)
	log.Info().
		Int64("total", s.statTotal.Load()).
		Int64("blocked", s.statBlocked.Load()).
		Int64("permitted", s.statPermitted.Load()).
		Int64("errors", s.statErrors.Load()).
		Int64("fail_open", s.statFailOpen.Load()).
		Msg("AISS agent stopped")
}

// Stats returns current request counters.
func (s *Server) Stats() map[string]int64 {
	return map[string]int64{
		"total":     s.statTotal.Load(),
		"blocked":   s.statBlocked.Load(),
		"permitted": s.statPermitted.Load(),
		"errors":    s.statErrors.Load(),
		"fail_open": s.statFailOpen.Load(),
	}
}

// handleConn processes a single connection from the C module.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	s.statTotal.Add(1)
	timeout := time.Duration(s.timeoutMs) * time.Millisecond

	// Set read deadline (Fail-Open if C module is slow)
	_ = conn.SetDeadline(time.Now().Add(timeout * 10))

	// Read request (newline-delimited JSON)
	buf := make([]byte, 64*1024) // 64 KB max request
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		s.failOpen(conn, "read error")
		s.statErrors.Add(1)
		return
	}

	var req Request
	if err := json.Unmarshal(trimNewline(buf[:n]), &req); err != nil {
		log.Warn().Err(err).Msg("malformed request JSON from C module")
		s.failOpen(conn, "json parse error")
		s.statErrors.Add(1)
		return
	}

	// Run security pipeline with timeout
	t0 := time.Now()
	resp := s.handler(&req)
	elapsed := time.Since(t0)

	// Fail-Open if pipeline exceeded timeout
	if elapsed > timeout {
		log.Warn().
			Str("ip", req.ClientIP).
			Dur("elapsed", elapsed).
			Dur("timeout", timeout).
			Msg("pipeline timeout — Fail-Open")
		s.failOpen(conn, "pipeline timeout")
		s.statFailOpen.Add(1)
		return
	}

	resp.LatencyMs = float64(elapsed.Microseconds()) / 1000.0

	data, err := json.Marshal(resp)
	if err != nil {
		s.failOpen(conn, "marshal error")
		s.statErrors.Add(1)
		return
	}
	data = append(data, '\n')

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
	if _, err := conn.Write(data); err != nil {
		s.statErrors.Add(1)
		return
	}

	if resp.Action == "BLOCK" {
		s.statBlocked.Add(1)
	} else {
		s.statPermitted.Add(1)
	}
}

// failOpen sends a PERMIT response to prevent the web server from stalling.
func (s *Server) failOpen(conn net.Conn, reason string) {
	resp := Response{Action: "PERMIT", Reason: "fail-open: " + reason, Tier: 0}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Millisecond))
	_, _ = conn.Write(data)
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
