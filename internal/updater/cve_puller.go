// Package updater handles background CVE delta pulls and model hot-swaps.
package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// CVEUpdate is a single CVE record from the server delta endpoint.
type CVEUpdate struct {
	ID              int     `json:"id"`
	CVEID           string  `json:"cve_id"`
	Pattern         string  `json:"pattern"`
	Severity        string  `json:"severity"`
	CVSS            float64 `json:"cvss"`
	AffectedProduct string  `json:"affected_product"`
	Active          bool    `json:"active"`
	ModifiedAt      string  `json:"modified_at"`
}

// PatternReloader is implemented by the Tier1 engine.
type PatternReloader interface {
	UpsertPattern(id int, cveID, pattern, severity string)
}

// DBConfig is implemented by the DB store for config persistence.
type DBConfig interface {
	GetConfig(key string) (string, bool)
	SetConfig(key, value string)
}

// CVEPuller polls the central server for CVE signature updates.
type CVEPuller struct {
	serverURL string
	agentID   string
	apiKey    string
	interval  time.Duration
	reloader  PatternReloader
	db        DBConfig
	client    *http.Client
	quit      chan struct{}
	done      chan struct{}
}

// NewCVEPuller creates and starts a CVE puller.
func NewCVEPuller(
	serverURL, agentID, apiKey string,
	intervalSec int,
	reloader PatternReloader,
	db DBConfig,
) *CVEPuller {
	p := &CVEPuller{
		serverURL: serverURL,
		agentID:   agentID,
		apiKey:    apiKey,
		interval:  time.Duration(intervalSec) * time.Second,
		reloader:  reloader,
		db:        db,
		client:    &http.Client{Timeout: 30 * time.Second},
		quit:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go p.run()
	log.Info().Dur("interval", p.interval).Msg("CVE puller started")
	return p
}

// Stop shuts down the puller.
func (p *CVEPuller) Stop() {
	close(p.quit)
	<-p.done
}

func (p *CVEPuller) run() {
	defer close(p.done)

	// Pull immediately on start
	p.pull()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.pull()
		case <-p.quit:
			return
		}
	}
}

func (p *CVEPuller) pull() {
	since := p.lastSyncTime()

	url := fmt.Sprintf("%s/v1/updates?since=%s&agent_id=%s",
		p.serverURL, since, p.agentID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Debug().Err(err).Msg("CVE puller: request build failed")
		return
	}
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	req.Header.Set("X-Agent-ID", p.agentID)

	resp, err := p.client.Do(req)
	if err != nil {
		log.Debug().Err(err).Str("url", url).Msg("CVE puller: server unreachable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug().Int("status", resp.StatusCode).Msg("CVE puller: unexpected status")
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB max
	if err != nil {
		log.Warn().Err(err).Msg("CVE puller: read response failed")
		return
	}

	var updates []CVEUpdate
	if err := json.Unmarshal(body, &updates); err != nil {
		log.Warn().Err(err).Msg("CVE puller: JSON parse failed")
		return
	}

	applied := 0
	for _, u := range updates {
		if u.Pattern == "" {
			continue
		}
		if p.reloader != nil {
			p.reloader.UpsertPattern(u.ID, u.CVEID, u.Pattern, u.Severity)
		}
		applied++
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if p.db != nil {
		p.db.SetConfig("last_cve_sync", now)
	}

	log.Info().Int("applied", applied).Str("since", since).Msg("CVE delta applied")
}

func (p *CVEPuller) lastSyncTime() string {
	if p.db != nil {
		if v, ok := p.db.GetConfig("last_cve_sync"); ok {
			return v
		}
	}
	// Default: pull last 7 days on first run
	return time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
}
