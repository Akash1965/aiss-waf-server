// AISS Agent — AI Security Shield
// High-performance ML-enabled security middleware for Nginx and Apache.
// Listens on a Unix Domain Socket, applies a 3-tier security pipeline,
// and returns PERMIT/BLOCK verdicts in milliseconds.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aiss/agent/internal/config"
	"github.com/aiss/agent/internal/db"
	"github.com/aiss/agent/internal/security"
	"github.com/aiss/agent/internal/socket"
	"github.com/aiss/agent/internal/telemetry"
	"github.com/aiss/agent/internal/updater"
)

var version = "dev"

func main() {
	// ── CLI flags ────────────────────────────────────────────────────────
	cfgPath := flag.String("config", "", "Path to aiss.conf (default: /etc/aiss/aiss.conf)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("AISS Agent %s (Go %s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// ── Configuration ────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: config load failed: %v\n", err)
		os.Exit(1)
	}

	// ── Logging ──────────────────────────────────────────────────────────
	setupLogging(cfg.LogLevel)

	log.Info().
		Str("version", version).
		Str("agent_id", cfg.AgentID).
		Str("mode", cfg.Mode).
		Str("socket", cfg.SocketPath).
		Str("db", cfg.DBPath).
		Msg("AISS agent starting")

	// ── Local database ────────────────────────────────────────────────────
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to open local database")
	}
	defer store.Close()

	// ── Telemetry buffer ─────────────────────────────────────────────────
	tel := telemetry.New(
		10_000,
		cfg.TelemetryBatchSize,
		time.Duration(float64(time.Second)*cfg.TelemetryFlushSec),
		telemetry.NoopSink{}, // replace with HTTP sink to send to central server
	)
	defer tel.Stop()

	// ── Security pipeline ─────────────────────────────────────────────────
	pipeline, err := security.NewPipeline(
		cfg.Mode,
		cfg.MLThreshold,
		cfg.PatternsFile,
		cfg.RulesDir,
		cfg.ContentFullScanLimit,
		cfg.ContentSampleLimit,
		int(cfg.VerdictCacheTTL.Seconds()),
		store,
		tel,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise security pipeline")
	}

	// ── CVE puller (background) ───────────────────────────────────────────
	puller := updater.NewCVEPuller(
		cfg.ServerURL,
		cfg.AgentID,
		cfg.APIKey,
		cfg.CVESyncIntervalSec,
		nil, // PatternReloader — wire up when integrating with tier1 engine
		store,
	)
	defer puller.Stop()

	// ── Socket server ─────────────────────────────────────────────────────
	srv := socket.New(
		cfg.SocketPath,
		func(req *socket.Request) *socket.Response {
			return pipeline.Check(req)
		},
		cfg.SocketTimeoutMs,
		cfg.MaxWorkers,
	)

	// ── Signal handling ────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				log.Info().Msg("SIGHUP received — reloading rules")
				pipeline.ReloadRules()
			case os.Interrupt, syscall.SIGTERM:
				log.Info().Msg("Shutdown signal received")
				srv.Stop()
				return
			}
		}
	}()

	// ── Start serving ─────────────────────────────────────────────────────
	if err := srv.Start(); err != nil {
		log.Fatal().Err(err).Msg("socket server error")
	}
}

func setupLogging(level string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	w := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

	var lvl zerolog.Level
	switch level {
	case "debug":
		lvl = zerolog.DebugLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	default:
		lvl = zerolog.InfoLevel
	}

	log.Logger = zerolog.New(w).Level(lvl).With().Timestamp().
		Str("service", "aiss-agent").Logger()
}
