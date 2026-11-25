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
		PollInterval: time.Minute,
		MaxLookback:  72 * time.Hour,
	}
}

func TestWindowStart_NoCheckpointUsesMaxLookback(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	got := coll.windowStart(datasetEmail, []string{outputSplunk}, now, cfg)
	assert.True(t, got.Equal(now.Add(-cfg.MaxLookback)))
}

func TestWindowStart_NewOutputBackfillsFully(t *testing.T) {
	t.Parallel()

	coll := newTestCollector(t)
	cfg := testConfig()
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

	// Splunk is current. OpenObserve is new, so the window must reach back fully.
	coll.store.advance(datasetHTTP, outputSplunk, now.Add(-time.Minute))

	got := coll.windowStart(datasetHTTP, []string{outputSplunk, outputOpenObserve}, now, cfg)
	assert.True(t, got.Equal(now.Add(-cfg.MaxLookback)))
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
// trimPage
// ---------------------------------------------------------------------------

type testRow struct {
	at time.Time
	id string
}

func rowTime(r testRow) time.Time { return r.at }

func TestTrimPage_NoFullGroup(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	groups := [][]testRow{
		{{start.Add(time.Second), "a"}, {start.Add(2 * time.Second), "b"}},
		{{start.Add(3 * time.Second), "c"}},
	}

	rows, pageEnd, more := trimPage(groups, 3, start, end, rowTime)
	assert.Len(t, rows, 3)
	assert.True(t, pageEnd.Equal(end))
	assert.False(t, more)
}

func TestTrimPage_OneFullGroup(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	cursor := start.Add(5 * time.Second)
	groups := [][]testRow{
		{{start.Add(time.Second), "a1"}, {start.Add(2 * time.Second), "a2"}, {cursor, "a3"}}, // full
		{{start.Add(time.Second), "b1"}, {start.Add(4 * time.Second), "b2"}, {start.Add(9 * time.Second), "b3"}},
	}

	rows, pageEnd, more := trimPage(groups, 3, start, end, rowTime)

	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.id)
	}

	assert.Equal(t, []string{"a1", "a2", "b1", "b2"}, ids)
	assert.True(t, pageEnd.Equal(cursor.Add(-time.Nanosecond)))
	assert.True(t, more)
}

func TestTrimPage_TwoFullGroupsUsesSmallerCursor(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	groups := [][]testRow{
		{{start.Add(time.Second), "a1"}, {start.Add(10 * time.Second), "a2"}},
		{{start.Add(2 * time.Second), "b1"}, {start.Add(6 * time.Second), "b2"}},
	}

	rows, pageEnd, more := trimPage(groups, 2, start, end, rowTime)
	assert.Len(t, rows, 2) // a1, b1
	assert.True(t, pageEnd.Equal(start.Add(6*time.Second-time.Nanosecond)))
	assert.True(t, more)
}

func TestTrimPage_NoProgressKeepsRows(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	groups := [][]testRow{
		{{start, "a"}, {start, "b"}, {start, "c"}},
	}

	rows, pageEnd, more := trimPage(groups, 3, start, end, rowTime)
	assert.Len(t, rows, 3)
	assert.True(t, pageEnd.Equal(start))
	assert.True(t, more)
}

// ---------------------------------------------------------------------------
// paginate
// ---------------------------------------------------------------------------

func TestPaginate_ContinuesUntilFinished(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Hour)

	var starts []time.Time

	done := paginate(start, now, func(s, end time.Time) (time.Time, bool) {
		starts = append(starts, s)

		if len(starts) < 3 {
			return s.Add(10*time.Minute - time.Nanosecond), true
		}

		return end, true
	})

	assert.True(t, done)
	require.Len(t, starts, 3)
	assert.True(t, starts[0].Equal(start))
	assert.True(t, starts[1].Equal(start.Add(10*time.Minute)))
	assert.True(t, starts[2].Equal(start.Add(20*time.Minute)))
}

func TestPaginate_ClampsToMaxQueryDuration(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start.Add(maxQueryDuration + 24*time.Hour)

	var ends []time.Time

	done := paginate(start, now, func(_, e time.Time) (time.Time, bool) {
		ends = append(ends, e)

		return e, true
	})

	assert.True(t, done)
	require.Len(t, ends, 2)
	assert.True(t, ends[0].Equal(start.Add(maxQueryDuration)))
	assert.True(t, ends[1].Equal(now))
}

func TestPaginate_StopsOnFailure(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	calls := 0

	done := paginate(start, start.Add(time.Hour), func(_, _ time.Time) (time.Time, bool) {
		calls++

		return time.Time{}, false
	})

	assert.False(t, done)
	assert.Equal(t, 1, calls)
}

func TestPaginate_StopsWhenNoProgress(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	calls := 0

	done := paginate(start, start.Add(time.Hour), func(s, _ time.Time) (time.Time, bool) {
		calls++

		return s.Add(-time.Second), true
	})

	assert.False(t, done)
	assert.Equal(t, 1, calls)
}

// ---------------------------------------------------------------------------
// sendBatches
// ---------------------------------------------------------------------------

func TestSendBatches_SplitsIntoBatches(t *testing.T) {
	t.Parallel()

	var sizes []int

	done := sendBatches(make([]int, 2500), 1000, func(b []int) bool {
		sizes = append(sizes, len(b))

		return true
	})

	assert.True(t, done)
	assert.Equal(t, []int{1000, 1000, 500}, sizes)
}

func TestSendBatches_StopsOnFirstFailure(t *testing.T) {
	t.Parallel()

	calls := 0

	done := sendBatches(make([]int, 2500), 1000, func([]int) bool {
		calls++

		return calls < 2
	})

	assert.False(t, done)
	assert.Equal(t, 2, calls)
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
