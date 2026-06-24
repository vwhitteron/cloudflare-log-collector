package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// checkpointStore
// ---------------------------------------------------------------------------

func TestCheckpointStore_LoadMissingFile(t *testing.T) {
	t.Parallel()

	store, err := loadState(filepath.Join(t.TempDir(), "does-not-exist.json"))
	require.NoError(t, err)
	assert.True(t, store.get(datasetHTTP, outputSplunk).IsZero())
}

func TestCheckpointStore_SaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	when := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	store, err := loadState(path)
	require.NoError(t, err)
	store.advance(datasetHTTP, outputSplunk, when)

	// Re-load from disk and confirm the checkpoint persisted.
	reloaded, err := loadState(path)
	require.NoError(t, err)
	assert.True(t, reloaded.get(datasetHTTP, outputSplunk).Equal(when))
	assert.True(t, reloaded.get(datasetHTTP, outputOpenObserve).IsZero())
}

func TestCheckpointStore_AdvanceNeverRegresses(t *testing.T) {
	t.Parallel()

	store, err := loadState("")
	require.NoError(t, err)

	later := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	earlier := later.Add(-time.Hour)

	store.advance(datasetR2, outputOpenObserve, later)
	store.advance(datasetR2, outputOpenObserve, earlier) // should be ignored

	assert.True(t, store.get(datasetR2, outputOpenObserve).Equal(later))
}

func TestCheckpointStore_EmptyPathIsInMemory(t *testing.T) {
	t.Parallel()

	store, err := loadState("")
	require.NoError(t, err)

	when := time.Now().UTC()
	store.advance(datasetHTTP, outputSplunk, when) // must not panic without a path
	assert.True(t, store.get(datasetHTTP, outputSplunk).Equal(when))
}

// ---------------------------------------------------------------------------
// windowStart
// ---------------------------------------------------------------------------

func newTestCollector(t *testing.T) *collector {
	t.Helper()

	store, err := loadState("")
	require.NoError(t, err)

	return newCollector(store)
}

func testConfig() *Config {
	return &Config{
		PollInterval:  time.Minute,
		MaxLookback:   72 * time.Hour,
		BackfillChunk: time.Minute,
	}
}

func TestWindowStart_NoCheckpointUsesPollInterval(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	got := coll.windowStart(datasetHTTP, []string{outputSplunk}, now, cfg)
	assert.True(t, got.Equal(now.Add(-cfg.PollInterval)))
}

func TestWindowStart_UsesOldestHealthyCheckpoint(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	// Splunk is behind by an hour, OpenObserve is current.
	coll.store.advance(datasetHTTP, outputSplunk, now.Add(-time.Hour))
	coll.store.advance(datasetHTTP, outputOpenObserve, now.Add(-time.Minute))

	got := coll.windowStart(datasetHTTP, []string{outputSplunk, outputOpenObserve}, now, cfg)
	assert.True(t, got.Equal(now.Add(-time.Hour)), "window must start at the oldest checkpoint")
}

func TestWindowStart_IgnoresUnhealthyOutput(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	// OpenObserve is far behind but is NOT in the healthy set, so it must not
	// drag the window back.
	coll.store.advance(datasetHTTP, outputOpenObserve, now.Add(-10*time.Hour))
	coll.store.advance(datasetHTTP, outputSplunk, now.Add(-2*time.Minute))

	got := coll.windowStart(datasetHTTP, []string{outputSplunk}, now, cfg)
	assert.True(t, got.Equal(now.Add(-2*time.Minute)))
}

func TestWindowStart_ClampsToMaxLookback(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	coll.store.advance(datasetR2, outputSplunk, now.Add(-200*time.Hour)) // older than 72h

	got := coll.windowStart(datasetR2, []string{outputSplunk}, now, cfg)
	assert.True(t, got.Equal(now.Add(-cfg.MaxLookback)))
}

// ---------------------------------------------------------------------------
// chunkBounds
// ---------------------------------------------------------------------------

func TestChunkBounds_SingleWindowWhenSmall(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(30 * time.Second)

	bounds := chunkBounds(start, end, time.Minute)
	require.Len(t, bounds, 1)
	assert.True(t, bounds[0][0].Equal(start))
	assert.True(t, bounds[0][1].Equal(end))
}

func TestChunkBounds_SplitsLargeGap(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(150 * time.Second)

	bounds := chunkBounds(start, end, time.Minute)
	require.Len(t, bounds, 3) // 60s, 60s, 30s

	// Contiguous and covering the whole range without gaps or overlaps.
	assert.True(t, bounds[0][0].Equal(start))
	assert.True(t, bounds[0][1].Equal(bounds[1][0]))
	assert.True(t, bounds[1][1].Equal(bounds[2][0]))
	assert.True(t, bounds[2][1].Equal(end))
}

func TestChunkBounds_EmptyWhenStartAtEnd(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	assert.Empty(t, chunkBounds(now, now, time.Minute))
}

// ---------------------------------------------------------------------------
// afterCheckpoint
// ---------------------------------------------------------------------------

func httpAt(ts string) LogEntry {
	return LogEntry{Dimensions: Dimensions{Datetime: ts}}
}

func TestAfterCheckpoint_ZeroKeepsAll(t *testing.T) {
	t.Parallel()

	logs := []LogEntry{httpAt("2026-06-24T12:00:00Z"), httpAt("2026-06-24T12:01:00Z")}
	got := afterCheckpoint(logs, time.Time{}, func(e LogEntry) string { return e.Dimensions.Datetime })
	assert.Len(t, got, 2)
}

func TestAfterCheckpoint_StrictlyAfterDedupesBoundary(t *testing.T) {
	t.Parallel()

	checkpoint := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	logs := []LogEntry{
		httpAt("2026-06-24T12:00:00Z"), // == checkpoint, already delivered, must drop
		httpAt("2026-06-24T12:00:30Z"), // after checkpoint, keep
	}

	got := afterCheckpoint(logs, checkpoint, func(e LogEntry) string { return e.Dimensions.Datetime })
	require.Len(t, got, 1)
	assert.Equal(t, "2026-06-24T12:00:30Z", got[0].Dimensions.Datetime)
}

func TestAfterCheckpoint_KeepsUnparseableTimestamps(t *testing.T) {
	t.Parallel()

	checkpoint := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	logs := []LogEntry{httpAt("not-a-time")}

	got := afterCheckpoint(logs, checkpoint, func(e LogEntry) string { return e.Dimensions.Datetime })
	assert.Len(t, got, 1, "must not drop data on unparseable timestamps")
}

// ---------------------------------------------------------------------------
// enabledOutputs
// ---------------------------------------------------------------------------

func TestEnabledOutputs(t *testing.T) {
	t.Parallel()

	assert.Empty(t, enabledOutputs(&Config{}))

	both := enabledOutputs(&Config{
		OpenObserveURL: "http://oo", OpenObserveUser: "u",
		SplunkURL: "http://s", SplunkToken: "tok",
	})
	assert.Equal(t, []string{outputOpenObserve, outputSplunk}, both)

	splunkOnly := enabledOutputs(&Config{SplunkURL: "http://s", SplunkToken: "tok"})
	assert.Equal(t, []string{outputSplunk}, splunkOnly)
}

// ---------------------------------------------------------------------------
// healthBaseURL
// ---------------------------------------------------------------------------

func TestHealthBaseURL(t *testing.T) {
	t.Parallel()

	base, err := healthBaseURL("https://logs.example.com:5080/api/default/_json")
	require.NoError(t, err)
	assert.Equal(t, "https://logs.example.com:5080", base)

	_, err = healthBaseURL("not a url")
	assert.Error(t, err)
}
