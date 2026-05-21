-- ─────────────────────────────────────────────────────────────────────────────
-- AISS Apache Doris Schema
-- Run once via: mysql -h doris-fe -P 9030 -u root < doris_schema.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS aiss;
USE aiss;

-- ── Security Events ───────────────────────────────────────────────────────────
-- DUPLICATE KEY model — append-only, optimised for time-series analytics.
-- Partitioned by day for fast pruning of old data.
CREATE TABLE IF NOT EXISTS security_events (
    created_at      DATETIME        NOT NULL,
    id              VARCHAR(64)     NOT NULL,
    agent_id        VARCHAR(64)     NOT NULL DEFAULT '',
    client_ip       VARCHAR(45)     NOT NULL DEFAULT '',
    method          VARCHAR(16)     NOT NULL DEFAULT '',
    uri             VARCHAR(2048)   NOT NULL DEFAULT '',
    action          VARCHAR(8)      NOT NULL DEFAULT 'PERMIT',
    tier            TINYINT         NOT NULL DEFAULT 0,
    cve_id          VARCHAR(32)     NOT NULL DEFAULT '',
    rule_name       VARCHAR(128)    NOT NULL DEFAULT '',
    reason          VARCHAR(1024)   NOT NULL DEFAULT '',
    ml_score        DOUBLE          NOT NULL DEFAULT 0.0,
    latency_ms      DOUBLE          NOT NULL DEFAULT 0.0,
    server_type     VARCHAR(16)     NOT NULL DEFAULT ''
)
DUPLICATE KEY(created_at, id)
PARTITION BY RANGE(created_at) (
    PARTITION p_history VALUES LESS THAN ("2025-01-01 00:00:00"),
    PARTITION p_2025_q1  VALUES LESS THAN ("2025-04-01 00:00:00"),
    PARTITION p_2025_q2  VALUES LESS THAN ("2025-07-01 00:00:00"),
    PARTITION p_2025_q3  VALUES LESS THAN ("2025-10-01 00:00:00"),
    PARTITION p_2025_q4  VALUES LESS THAN ("2026-01-01 00:00:00"),
    PARTITION p_2026_q1  VALUES LESS THAN ("2026-04-01 00:00:00"),
    PARTITION p_2026_q2  VALUES LESS THAN ("2026-07-01 00:00:00"),
    PARTITION p_2026_q3  VALUES LESS THAN ("2026-10-01 00:00:00"),
    PARTITION p_future   VALUES LESS THAN ("2099-01-01 00:00:00")
)
DISTRIBUTED BY HASH(agent_id) BUCKETS 16
PROPERTIES (
    "replication_num" = "1",
    "dynamic_partition.enable"         = "true",
    "dynamic_partition.time_unit"      = "DAY",
    "dynamic_partition.start"          = "-90",
    "dynamic_partition.end"            = "7",
    "dynamic_partition.prefix"         = "p",
    "dynamic_partition.buckets"        = "16",
    "dynamic_partition.replication_num"= "1"
);

-- ── CVE Signatures ────────────────────────────────────────────────────────────
-- UNIQUE KEY model — upserts keep the latest version of each CVE signature.
CREATE TABLE IF NOT EXISTS cve_signatures (
    cve_id          VARCHAR(32)     NOT NULL,
    name            VARCHAR(256)    NOT NULL DEFAULT '',
    description     VARCHAR(2048)   NOT NULL DEFAULT '',
    pattern         VARCHAR(2048)   NOT NULL,
    flags           VARCHAR(32)     NOT NULL DEFAULT '',
    severity        VARCHAR(16)     NOT NULL DEFAULT 'MEDIUM',
    cvss            DOUBLE          NOT NULL DEFAULT 0.0,
    affected_product VARCHAR(256)   NOT NULL DEFAULT '',
    active          BOOLEAN         NOT NULL DEFAULT TRUE,
    source          VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    modified_at     DATETIME        NOT NULL
)
UNIQUE KEY(cve_id)
DISTRIBUTED BY HASH(cve_id) BUCKETS 4
PROPERTIES ("replication_num" = "1");

-- ── Registered Agents ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    id              VARCHAR(64)     NOT NULL,
    hostname        VARCHAR(256)    NOT NULL DEFAULT '',
    ip              VARCHAR(45)     NOT NULL DEFAULT '',
    server_type     VARCHAR(16)     NOT NULL DEFAULT '',
    version         VARCHAR(32)     NOT NULL DEFAULT '',
    mode            VARCHAR(16)     NOT NULL DEFAULT 'shadow',
    last_seen       DATETIME,
    created_at      DATETIME        NOT NULL
)
UNIQUE KEY(id)
DISTRIBUTED BY HASH(id) BUCKETS 4
PROPERTIES ("replication_num" = "1");

-- ── Aggregated Hourly Stats (materialized for dashboard speed) ────────────────
CREATE TABLE IF NOT EXISTS hourly_stats (
    hour            DATETIME        NOT NULL,
    agent_id        VARCHAR(64)     NOT NULL DEFAULT '',
    total_requests  BIGINT          NOT NULL DEFAULT 0,
    total_blocked   BIGINT          NOT NULL DEFAULT 0,
    tier1_blocks    BIGINT          NOT NULL DEFAULT 0,
    tier2_blocks    BIGINT          NOT NULL DEFAULT 0,
    tier3_blocks    BIGINT          NOT NULL DEFAULT 0,
    content_blocks  BIGINT          NOT NULL DEFAULT 0
)
AGGREGATE KEY(hour, agent_id)
DISTRIBUTED BY HASH(agent_id) BUCKETS 4
PROPERTIES ("replication_num" = "1");
