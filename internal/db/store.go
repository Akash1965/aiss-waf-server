// Package db provides the local DuckDB store.
// DuckDB gives the agent analytical query power (window functions, columnar storage)
// without requiring a separate database process — it runs in-process via CGO.
package db

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	_ "github.com/marcboeker/go-duckdb" // DuckDB embedded analytics engine
)

const schema = `
CREATE TABLE IF NOT EXISTS cve_signatures (
	id          INTEGER PRIMARY KEY,
	cve_id      VARCHAR NOT NULL,
	pattern     VARCHAR NOT NULL,
	severity    VARCHAR DEFAULT 'MEDIUM',
	active      INTEGER DEFAULT 1,
	loaded_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ip_reputation (
	ip          VARCHAR PRIMARY KEY,
	verdict     VARCHAR NOT NULL,
	reason      VARCHAR,
	cve_id      VARCHAR,
	expires_at  TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS file_hashes (
	sha256      VARCHAR PRIMARY KEY,
	verdict     VARCHAR NOT NULL,
	threat_name VARCHAR,
	scanned_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS agent_config (
	key         VARCHAR PRIMARY KEY,
	value       VARCHAR NOT NULL,
	updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS security_events (
	id          VARCHAR PRIMARY KEY,
	client_ip   VARCHAR,
	method      VARCHAR,
	uri         VARCHAR,
	action      VARCHAR,
	tier        INTEGER,
	cve_id      VARCHAR,
	rule_name   VARCHAR,
	reason      VARCHAR,
	ml_score    DOUBLE,
	latency_ms  DOUBLE,
	created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_action  ON security_events(action);
CREATE INDEX IF NOT EXISTS idx_events_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_ip_expires     ON ip_reputation(expires_at);
`

// Store is the thread-safe local database wrapper.
// All writes are serialised through a single writer goroutine.
type Store struct {
	readDB    *sql.DB
	readMu    sync.Mutex
	writeCh   chan writeOp
	quit      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

type writeOp struct {
	sql    string
	args   []interface{}
	result chan<- error
}

// Open opens (or creates) the DuckDB database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, fmt.Errorf("open db %s: %w", path, err)
	}
	// DuckDB handles its own concurrency — single connection is fine for writes
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	s := &Store{
		readDB:  db,
		writeCh: make(chan writeOp, 10000),
		quit:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop(db)
	log.Info().Str("path", path).Msg("DuckDB store opened")
	return s, nil
}

// Close shuts down the store gracefully.
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		close(s.quit)
		s.wg.Wait()
		_ = s.readDB.Close()
	})
}

// ── IP Reputation ─────────────────────────────────────────────────────────

func (s *Store) GetIPVerdict(ip string) (verdict, reason string, found bool) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	row := s.readDB.QueryRow(
		`SELECT verdict, reason FROM ip_reputation
		 WHERE ip=? AND expires_at > CURRENT_TIMESTAMP`, ip)
	err := row.Scan(&verdict, &reason)
	if err != nil {
		return "", "", false
	}
	return verdict, reason, true
}

func (s *Store) SetIPVerdict(ip, verdict, reason, cveID string, ttlSec int) {
	expires := time.Now().UTC().Add(time.Duration(ttlSec) * time.Second).
		Format("2006-01-02 15:04:05")
	s.asyncWrite(
		`INSERT OR REPLACE INTO ip_reputation(ip,verdict,reason,cve_id,expires_at)
		 VALUES(?,?,?,?,?)`,
		ip, verdict, reason, cveID, expires)
}

func (s *Store) CleanExpiredIPs() {
	s.asyncWrite(`DELETE FROM ip_reputation WHERE expires_at <= CURRENT_TIMESTAMP`)
}

// ── File Hash Cache ────────────────────────────────────────────────────────

func (s *Store) GetFileHash(sha256 string) (verdict, threatName string, found bool) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	row := s.readDB.QueryRow(
		`SELECT verdict, COALESCE(threat_name,'') FROM file_hashes WHERE sha256=?`, sha256)
	err := row.Scan(&verdict, &threatName)
	if err != nil {
		return "", "", false
	}
	return verdict, threatName, true
}

func (s *Store) StoreFileHash(sha256, verdict, threatName string) {
	s.asyncWrite(
		`INSERT OR REPLACE INTO file_hashes(sha256,verdict,threat_name) VALUES(?,?,?)`,
		sha256, verdict, threatName)
}

// ── CVE Signatures ────────────────────────────────────────────────────────

func (s *Store) GetActiveSignatures() ([]CVESignature, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	rows, err := s.readDB.Query(
		`SELECT id,cve_id,pattern,severity FROM cve_signatures WHERE active=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sigs []CVESignature
	for rows.Next() {
		var sig CVESignature
		if err := rows.Scan(&sig.ID, &sig.CVEID, &sig.Pattern, &sig.Severity); err != nil {
			continue
		}
		sigs = append(sigs, sig)
	}
	return sigs, rows.Err()
}

func (s *Store) UpsertSignature(id int, cveID, pattern, severity string) {
	s.asyncWrite(
		`INSERT OR REPLACE INTO cve_signatures(id,cve_id,pattern,severity,active)
		 VALUES(?,?,?,?,1)`,
		id, cveID, pattern, severity)
}

// ── Agent Config ──────────────────────────────────────────────────────────

func (s *Store) GetConfig(key string) (string, bool) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var val string
	err := s.readDB.QueryRow(`SELECT value FROM agent_config WHERE key=?`, key).Scan(&val)
	if err != nil {
		return "", false
	}
	return val, true
}

func (s *Store) SetConfig(key, value string) {
	s.asyncWrite(
		`INSERT OR REPLACE INTO agent_config(key,value) VALUES(?,?)`, key, value)
}

// ── Security Events ────────────────────────────────────────────────────────

func (s *Store) StoreEvent(e SecurityEvent) {
	s.asyncWrite(
		`INSERT INTO security_events(id,client_ip,method,uri,action,tier,cve_id,rule_name,reason,ml_score,latency_ms)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.ClientIP, e.Method, e.URI, e.Action, e.Tier,
		e.CVEID, e.RuleName, e.Reason, e.MLScore, e.LatencyMs)
}

func (s *Store) GetRecentEvents(limit int, action string) ([]SecurityEvent, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	query := `SELECT id,client_ip,method,uri,action,tier,COALESCE(cve_id,''),COALESCE(rule_name,''),reason,ml_score,latency_ms,created_at
	          FROM security_events`
	var args []interface{}
	if action != "" {
		query += " WHERE action=?"
		args = append(args, action)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d", limit)

	rows, err := s.readDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.ClientIP, &e.Method, &e.URI, &e.Action,
			&e.Tier, &e.CVEID, &e.RuleName, &e.Reason, &e.MLScore, &e.LatencyMs, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) GetStats() (Stats, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	var stats Stats
	_ = s.readDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&stats.TotalEvents)
	_ = s.readDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE action='BLOCK'`).Scan(&stats.TotalBlocked)
	stats.TotalPermitted = stats.TotalEvents - stats.TotalBlocked

	rows, err := s.readDB.Query(
		`SELECT cve_id, COUNT(*) as cnt FROM security_events
		 WHERE cve_id!='' GROUP BY cve_id ORDER BY cnt DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cve TopCVE
			if err := rows.Scan(&cve.CVEID, &cve.Count); err == nil {
				stats.TopCVEs = append(stats.TopCVEs, cve)
			}
		}
	}
	return stats, nil
}

// ── Domain types ──────────────────────────────────────────────────────────

type CVESignature struct {
	ID       int
	CVEID    string
	Pattern  string
	Severity string
}

type SecurityEvent struct {
	ID        string
	ClientIP  string
	Method    string
	URI       string
	Action    string
	Tier      int
	CVEID     string
	RuleName  string
	Reason    string
	MLScore   float64
	LatencyMs float64
	CreatedAt string
}

type Stats struct {
	TotalEvents    int64
	TotalBlocked   int64
	TotalPermitted int64
	TopCVEs        []TopCVE
}

type TopCVE struct {
	CVEID string
	Count int64
}

// ── Internal write loop ────────────────────────────────────────────────────

func (s *Store) asyncWrite(query string, args ...interface{}) {
	select {
	case s.writeCh <- writeOp{sql: query, args: args}:
	default:
		log.Warn().Msg("DB write queue full — event dropped")
	}
}

func (s *Store) writeLoop(db *sql.DB) {
	defer s.wg.Done()
	for {
		select {
		case op := <-s.writeCh:
			// Drain batch for efficiency
			ops := []writeOp{op}
		drain:
			for len(ops) < 200 {
				select {
				case next := <-s.writeCh:
					ops = append(ops, next)
				default:
					break drain
				}
			}
			tx, err := db.Begin()
			if err != nil {
				log.Error().Err(err).Msg("db begin tx")
				continue
			}
			for _, o := range ops {
				if _, err := tx.Exec(o.sql, o.args...); err != nil {
					log.Debug().Err(err).Str("sql", o.sql).Msg("db exec")
				}
				if o.result != nil {
					o.result <- err
				}
			}
			if err := tx.Commit(); err != nil {
				log.Error().Err(err).Msg("db commit")
				_ = tx.Rollback()
			}
		case <-s.quit:
			// Flush remaining writes
			for len(s.writeCh) > 0 {
				op := <-s.writeCh
				_, _ = db.Exec(op.sql, op.args...)
			}
			return
		}
	}
}
