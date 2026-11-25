package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildEmailGraphQLQuery(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	end := start.Add(time.Hour)

	query := buildEmailGraphQLQuery([]string{"z1", "z2"}, false, start, end)

	for _, want := range []string{
		"emailRoutingAdaptive", "datetime_ASC", "limit: 10000", "zoneTag",
		start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano),
	} {
		if !strings.Contains(query, want) {
			t.Errorf("query missing %q:\n%s", want, query)
		}
	}

	if strings.Contains(query, "subject") {
		t.Error("subject must be absent when includeSubject is false")
	}

	if strings.Count(query, "{") != strings.Count(query, "}") {
		t.Error("unbalanced braces")
	}

	query = buildEmailGraphQLQuery([]string{"z1"}, true, start, end)
	if !strings.Contains(query, "subject") {
		t.Error("subject must be present when includeSubject is true")
	}

	if strings.Count(query, "{") != strings.Count(query, "}") {
		t.Error("unbalanced braces with subject")
	}
}

func TestProcessEmailAttempt(t *testing.T) {
	t.Parallel()

	col := newCollector(nil)
	col.zoneNames["z1"] = "one.example.com"

	body := []byte(`{"data":{"viewer":{"zones":[
		{"zoneTag":"z1","emailRoutingAdaptive":[{"datetime":"2026-01-01T00:00:00Z","sessionId":"a","isSpam":1}]},
		{"zoneTag":"z2","emailRoutingAdaptive":[{"datetime":"2026-01-01T00:00:01Z","sessionId":"b"},{"datetime":"2026-01-01T00:00:02Z","sessionId":"c"}]}
	]}}}`)

	groups, err := col.processEmailAttempt(body)
	if err != nil {
		t.Fatal(err)
	}

	logs := slices.Concat(groups...)

	if len(logs) != 3 {
		t.Fatalf("got %d logs, want 3", len(logs))
	}

	if logs[0].ZoneTag != "z1" || logs[0].ZoneName != "one.example.com" || logs[0].IsSpam != 1 {
		t.Errorf("unexpected first entry: %+v", logs[0])
	}

	if logs[1].ZoneTag != "z2" || logs[2].ZoneTag != "z2" {
		t.Errorf("zone tags not set per row: %+v", logs)
	}

	_, err = col.processEmailAttempt([]byte(`{"errors":[{"message":"boom"}]}`))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected GraphQL error, got %v", err)
	}
}

func TestDedupeEmail(t *testing.T) {
	t.Parallel()

	input := []EmailLogEntry{
		{SessionID: "a", Datetime: "t1"},
		{SessionID: "a", Datetime: "t1"},
		{SessionID: "a", Datetime: "t2"},
		{SessionID: "b", Datetime: "t1"},
	}

	out := dedupeEmail(input)
	if len(out) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(out), out)
	}

	if out[0].Datetime != "t1" || out[1].Datetime != "t2" || out[2].SessionID != "b" {
		t.Errorf("order not preserved: %+v", out)
	}
}

func TestApplyConfigKeyEmail(t *testing.T) {
	t.Parallel()

	cfg := &Config{}

	err := applyConfigKey(cfg, "email_routing", "true")
	if err != nil || !cfg.EmailRouting {
		t.Errorf("email_routing not set: err=%v", err)
	}

	err = applyConfigKey(cfg, "email_include_subject", "true")
	if err != nil || !cfg.EmailIncludeSubject {
		t.Errorf("email_include_subject not set: err=%v", err)
	}

	err = applyConfigKey(cfg, "email_routing", "maybe")
	if err == nil {
		t.Error("expected error for invalid email_routing")
	}

	err = applyConfigKey(cfg, "email_include_subject", "maybe")
	if err == nil {
		t.Error("expected error for invalid email_include_subject")
	}
}

func TestBuildEmailSplunkPayload(t *testing.T) {
	t.Parallel()

	logs := []EmailLogEntry{
		{SessionID: "a", Datetime: "2026-01-01T00:00:00Z"},
		{SessionID: "b", Datetime: "2026-01-01T00:00:01Z"},
	}

	buf, err := buildEmailSplunkPayload(logs)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}

	for _, l := range lines {
		if !strings.Contains(l, `"time":`) || !strings.Contains(l, `"sourcetype":"_json"`) {
			t.Errorf("line missing time/sourcetype: %s", l)
		}
	}
}
