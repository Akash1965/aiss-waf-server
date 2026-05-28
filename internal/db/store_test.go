package db_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiss/agent/internal/db"
)

// openTestDB creates a temporary SQLite database for testing.
func openTestDB(t *testing.T) *db.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	store, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// ── Open / schema ─────────────────────────────────────────────────────────

func TestOpen_CreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiss.db")
	store, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("database file should have been created on disk")
	}
}

func TestOpen_InMemory(t *testing.T) {
	store, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("in-memory Open failed: %v", err)
	}
	defer store.Close()
}

func TestOpen_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiss.db")

	// Open twice — should not corrupt schema
	s1, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := db.Open(path)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}
	defer s2.Close()
}

// ── IP Verdict ────────────────────────────────────────────────────────────

func TestIPVerdict_GetSetCycle(t *testing.T) {
	store := openTestDB(t)

	// Not found before setting
	_, _, found := store.GetIPVerdict("1.2.3.4")
	if found {
		t.Error("IP should not be found before SetIPVerdict")
	}

	// Set a BLOCK verdict
	store.SetIPVerdict("1.2.3.4", "BLOCK", "CVE match", "CVE-2021-44228", 60)
	time.Sleep(100 * time.Millisecond) // allow async write

	verdict, reason, found := store.GetIPVerdict("1.2.3.4")
	if !found {
		t.Fatal("IP verdict should be found after SetIPVerdict")
	}
	if verdict != "BLOCK" {
		t.Errorf("expected BLOCK, got %s", verdict)
	}
	if reason != "CVE match" {
		t.Errorf("expected reason 'CVE match', got %s", reason)
	}
}

func TestIPVerdict_PermitVerdict(t *testing.T) {
	store := openTestDB(t)
	store.SetIPVerdict("5.6.7.8", "PERMIT", "clean scan", "", 60)
	time.Sleep(100 * time.Millisecond)

	verdict, _, found := store.GetIPVerdict("5.6.7.8")
	if !found {
		t.Fatal("PERMIT verdict should be stored")
	}
	if verdict != "PERMIT" {
		t.Errorf("expected PERMIT, got %s", verdict)
	}
}

func TestIPVerdict_Overwrite(t *testing.T) {
	store := openTestDB(t)
	store.SetIPVerdict("9.9.9.9", "PERMIT", "initial", "", 60)
	time.Sleep(50 * time.Millisecond)
	store.SetIPVerdict("9.9.9.9", "BLOCK", "re-evaluated", "CVE-2014-6271", 60)
	time.Sleep(100 * time.Millisecond)

	verdict, reason, found := store.GetIPVerdict("9.9.9.9")
	if !found {
		t.Fatal("IP should be found")
	}
	if verdict != "BLOCK" {
		t.Errorf("expected updated verdict BLOCK, got %s", verdict)
	}
	if reason != "re-evaluated" {
		t.Errorf("expected updated reason, got %s", reason)
	}
}

func TestIPVerdict_MultipleIPs(t *testing.T) {
	store := openTestDB(t)
	ips := map[string]string{
		"10.0.0.1": "BLOCK",
		"10.0.0.2": "PERMIT",
		"10.0.0.3": "BLOCK",
	}
	for ip, v := range ips {
		store.SetIPVerdict(ip, v, "test", "", 60)
	}
	time.Sleep(150 * time.Millisecond)

	for ip, expected := range ips {
		verdict, _, found := store.GetIPVerdict(ip)
		if !found {
			t.Errorf("IP %s should be found", ip)
			continue
		}
		if verdict != expected {
			t.Errorf("IP %s: expected %s, got %s", ip, expected, verdict)
		}
	}
}

// ── File Hash ─────────────────────────────────────────────────────────────

func TestFileHash_GetSetCycle(t *testing.T) {
	store := openTestDB(t)
	sha := "abababababababababababababababababababababababababababababababababab"

	_, _, found := store.GetFileHash(sha)
	if found {
		t.Error("hash should not be found before StoreFileHash")
	}

	store.StoreFileHash(sha, "MALICIOUS", "Trojan.Generic")
	time.Sleep(100 * time.Millisecond)

	verdict, threat, found := store.GetFileHash(sha)
	if !found {
		t.Fatal("hash should be found after StoreFileHash")
	}
	if verdict != "MALICIOUS" {
		t.Errorf("expected MALICIOUS, got %s", verdict)
	}
	if threat != "Trojan.Generic" {
		t.Errorf("expected 'Trojan.Generic', got %s", threat)
	}
}

func TestFileHash_CleanVerdict(t *testing.T) {
	store := openTestDB(t)
	sha := "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	store.StoreFileHash(sha, "CLEAN", "")
	time.Sleep(100 * time.Millisecond)

	verdict, threat, found := store.GetFileHash(sha)
	if !found {
		t.Fatal("clean hash should be stored")
	}
	if verdict != "CLEAN" {
		t.Errorf("expected CLEAN, got %s", verdict)
	}
	if threat != "" {
		t.Errorf("threat name should be empty for CLEAN, got %s", threat)
	}
}

func TestFileHash_Overwrite(t *testing.T) {
	store := openTestDB(t)
	sha := "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
	store.StoreFileHash(sha, "CLEAN", "")
	time.Sleep(50 * time.Millisecond)
	store.StoreFileHash(sha, "MALICIOUS", "Webshell.PHP")
	time.Sleep(100 * time.Millisecond)

	verdict, threat, _ := store.GetFileHash(sha)
	if verdict != "MALICIOUS" {
		t.Errorf("expected updated verdict MALICIOUS, got %s", verdict)
	}
	if threat != "Webshell.PHP" {
		t.Errorf("expected 'Webshell.PHP', got %s", threat)
	}
}

// ── CVE Signatures ────────────────────────────────────────────────────────

func TestSignatures_UpsertAndRetrieve(t *testing.T) {
	store := openTestDB(t)
	store.UpsertSignature(1, "CVE-2021-44228", `\$\{jndi:`, "CRITICAL")
	store.UpsertSignature(2, "CVE-2014-6271", `\(\)\s*\{`, "CRITICAL")
	time.Sleep(150 * time.Millisecond)

	sigs, err := store.GetActiveSignatures()
	if err != nil {
		t.Fatalf("GetActiveSignatures failed: %v", err)
	}
	if len(sigs) < 2 {
		t.Errorf("expected >= 2 signatures, got %d", len(sigs))
	}

	found := false
	for _, s := range sigs {
		if s.CVEID == "CVE-2021-44228" {
			found = true
			if s.Severity != "CRITICAL" {
				t.Errorf("expected CRITICAL severity, got %s", s.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("CVE-2021-44228 should appear in active signatures")
	}
}

func TestSignatures_UpsertIdempotent(t *testing.T) {
	store := openTestDB(t)
	store.UpsertSignature(10, "CVE-2022-22965", `class\.module`, "CRITICAL")
	store.UpsertSignature(10, "CVE-2022-22965", `class\.module\.classLoader`, "CRITICAL")
	time.Sleep(150 * time.Millisecond)

	sigs, err := store.GetActiveSignatures()
	if err != nil {
		t.Fatalf("GetActiveSignatures failed: %v", err)
	}
	count := 0
	for _, s := range sigs {
		if s.CVEID == "CVE-2022-22965" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("upsert should not duplicate: expected 1 signature with that CVE, got %d", count)
	}
}

// ── Agent Config ──────────────────────────────────────────────────────────

func TestConfig_GetSetCycle(t *testing.T) {
	store := openTestDB(t)

	_, found := store.GetConfig("last_cve_sync")
	if found {
		t.Error("config key should not exist before SetConfig")
	}

	store.SetConfig("last_cve_sync", "2026-05-10T00:00:00Z")
	time.Sleep(100 * time.Millisecond)

	val, found := store.GetConfig("last_cve_sync")
	if !found {
		t.Fatal("config key should be found after SetConfig")
	}
	if val != "2026-05-10T00:00:00Z" {
		t.Errorf("expected '2026-05-10T00:00:00Z', got %q", val)
	}
}

func TestConfig_Overwrite(t *testing.T) {
	store := openTestDB(t)
	store.SetConfig("mode", "shadow")
	time.Sleep(50 * time.Millisecond)
	store.SetConfig("mode", "enforce")
	time.Sleep(100 * time.Millisecond)

	val, _ := store.GetConfig("mode")
	if val != "enforce" {
		t.Errorf("expected 'enforce' after overwrite, got %q", val)
	}
}

func TestConfig_MultipleKeys(t *testing.T) {
	store := openTestDB(t)
	store.SetConfig("key_a", "value_a")
	store.SetConfig("key_b", "value_b")
	store.SetConfig("key_c", "value_c")
	time.Sleep(150 * time.Millisecond)

	pairs := map[string]string{"key_a": "value_a", "key_b": "value_b", "key_c": "value_c"}
	for k, expected := range pairs {
		val, found := store.GetConfig(k)
		if !found {
			t.Errorf("key %q should be found", k)
			continue
		}
		if val != expected {
			t.Errorf("key %q: expected %q, got %q", k, expected, val)
		}
	}
}

// ── Security Events ───────────────────────────────────────────────────────

func TestEvents_StoreAndRetrieve(t *testing.T) {
	store := openTestDB(t)
	store.StoreEvent(db.SecurityEvent{
		ID:       "event-001",
		ClientIP: "1.2.3.4",
		Method:   "GET",
		URI:      "/api/exploit",
		Action:   "BLOCK",
		Tier:     1,
		CVEID:    "CVE-2021-44228",
		Reason:   "Log4Shell",
	})
	time.Sleep(150 * time.Millisecond)

	events, err := store.GetRecentEvents(10, "")
	if err != nil {
		t.Fatalf("GetRecentEvents failed: %v", err)
	}
	if len(events) == 0 {
		t.Error("should have at least one stored event")
	}
}

func TestEvents_LimitRespected(t *testing.T) {
	store := openTestDB(t)
	for i := 0; i < 20; i++ {
		store.StoreEvent(db.SecurityEvent{
			ID:     "evt-" + string(rune('a'+i)),
			Action: "PERMIT",
		})
	}
	time.Sleep(200 * time.Millisecond)

	events, err := store.GetRecentEvents(5, "")
	if err != nil {
		t.Fatalf("GetRecentEvents failed: %v", err)
	}
	if len(events) > 5 {
		t.Errorf("GetRecentEvents(5) should return at most 5 events, got %d", len(events))
	}
}

func TestEvents_FilterByAction(t *testing.T) {
	store := openTestDB(t)
	store.StoreEvent(db.SecurityEvent{ID: "e1", Action: "BLOCK"})
	store.StoreEvent(db.SecurityEvent{ID: "e2", Action: "PERMIT"})
	store.StoreEvent(db.SecurityEvent{ID: "e3", Action: "BLOCK"})
	time.Sleep(150 * time.Millisecond)

	blocked, err := store.GetRecentEvents(10, "BLOCK")
	if err != nil {
		t.Fatalf("GetRecentEvents with filter failed: %v", err)
	}
	for _, e := range blocked {
		if e.Action != "BLOCK" {
			t.Errorf("filter BLOCK: got event with action %s", e.Action)
		}
	}
}

// ── Stats ─────────────────────────────────────────────────────────────────

func TestStats_ReturnsCounts(t *testing.T) {
	store := openTestDB(t)
	store.StoreEvent(db.SecurityEvent{ID: "s1", Action: "BLOCK"})
	store.StoreEvent(db.SecurityEvent{ID: "s2", Action: "PERMIT"})
	store.StoreEvent(db.SecurityEvent{ID: "s3", Action: "BLOCK"})
	time.Sleep(150 * time.Millisecond)

	stats, err := store.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalEvents < 3 {
		t.Errorf("expected TotalEvents >= 3, got %d", stats.TotalEvents)
	}
	if stats.TotalBlocked < 2 {
		t.Errorf("expected TotalBlocked >= 2, got %d", stats.TotalBlocked)
	}
}

// ── Close idempotent ──────────────────────────────────────────────────────

func TestClose_Idempotent(t *testing.T) {
	dir := t.TempDir()
	store, _ := db.Open(filepath.Join(dir, "close.db"))
	store.Close()
	store.Close() // second close should not panic
}

// ── Concurrency ───────────────────────────────────────────────────────────

func TestStore_ConcurrentWrites(t *testing.T) {
	store := openTestDB(t)
	done := make(chan struct{})

	for g := 0; g < 10; g++ {
		go func(id int) {
			for i := 0; i < 50; i++ {
				ip := "192.168.1." + string(rune('0'+id))
				store.SetIPVerdict(ip, "BLOCK", "concurrent test", "", 60)
			}
			done <- struct{}{}
		}(g)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	time.Sleep(200 * time.Millisecond)
	// No panic, no deadlock = success
}
