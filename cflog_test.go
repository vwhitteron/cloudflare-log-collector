package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// parseQuery is a helper that parses a GraphQL query and fails the test on error.
func parseQuery(t *testing.T, query string) *ast.QueryDocument {
	t.Helper()

	doc, err := parser.ParseQuery(&ast.Source{Input: query})
	require.NoError(t, err, "GraphQL query must be syntactically valid")

	return doc
}

// fieldNames recursively collects all field names from a selection set.
func fieldNames(ss ast.SelectionSet) []string {
	var names []string

	for _, sel := range ss {
		if s, ok := sel.(*ast.Field); ok {
			names = append(names, s.Name)
			names = append(names, fieldNames(s.SelectionSet)...)
		}
	}

	return names
}

//nolint:gochecknoglobals // shared time fixtures for query tests
var (
	fixedStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedEnd   = fixedStart.Add(5 * time.Minute)
)

// ---------------------------------------------------------------------------
// buildZonesCall
// ---------------------------------------------------------------------------

func TestBuildZonesCall_NoFilter(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "zones", buildZonesCall(nil))
	assert.Equal(t, "zones", buildZonesCall([]string{}))
}

func TestBuildZonesCall_SingleZone(t *testing.T) {
	t.Parallel()

	got := buildZonesCall([]string{"abc123"})
	assert.Equal(t, `zones(filter: {zoneTag: "abc123"})`, got)
}

func TestBuildZonesCall_MultipleZones(t *testing.T) {
	t.Parallel()

	got := buildZonesCall([]string{"aaa", "bbb", "ccc"})
	assert.Contains(t, got, "zoneTag_in")
	assert.Contains(t, got, `"aaa"`)
	assert.Contains(t, got, `"bbb"`)
	assert.Contains(t, got, `"ccc"`)
}

// ---------------------------------------------------------------------------
// buildGraphQLQuery — syntax
// ---------------------------------------------------------------------------

func TestBuildGraphQLQuery_ValidSyntax_PrimarySelector(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	parseQuery(t, q) // fails if not valid GraphQL
}

func TestBuildGraphQLQuery_ValidSyntax_AliasSelector(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName: clientRequestHTTPMethod", fixedStart, fixedEnd, nil)
	parseQuery(t, q)
}

func TestBuildGraphQLQuery_ValidSyntax_NoneSelector(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", methodSelectorNone, fixedStart, fixedEnd, nil)
	parseQuery(t, q) // must still be valid GraphQL without a method field
	assert.NotContains(t, q, "clientRequestHTTPMethodName", "method name field must be absent when using none selector")
	assert.NotContains(t, q, "clientRequestHTTPMethod\"", "method alias field must be absent when using none selector")
}

func TestBuildGraphQLQuery_ValidSyntax_SingleZone(t *testing.T) {
	t.Parallel()

	zonesCall := buildZonesCall([]string{"abc123"})
	q := buildGraphQLQuery(zonesCall, "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	parseQuery(t, q)
}

func TestBuildGraphQLQuery_ValidSyntax_MultiZone(t *testing.T) {
	t.Parallel()

	zonesCall := buildZonesCall([]string{"aaa", "bbb"})
	q := buildGraphQLQuery(zonesCall, "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	parseQuery(t, q)
}

// ---------------------------------------------------------------------------
// buildGraphQLQuery — field presence / absence
// ---------------------------------------------------------------------------

// TestBuildGraphQLQuery_NoZoneName asserts that the query never requests
// the `zoneName` field, which is not exposed by Cloudflare's GraphQL schema
// and will cause an "unknown field" error if included.
func TestBuildGraphQLQuery_NoZoneName(t *testing.T) {
	t.Parallel()

	for _, sel := range []string{"clientRequestHTTPMethodName", "clientRequestHTTPMethodName: clientRequestHTTPMethod"} {
		q := buildGraphQLQuery("zones", sel, fixedStart, fixedEnd, nil)
		assert.NotContains(t, q, "zoneName",
			"query must not request zoneName (not in Cloudflare schema): selector=%q", sel)
	}
}

func TestBuildGraphQLQuery_RequiredFields(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	doc := parseQuery(t, q)

	names := fieldNames(doc.Operations[0].SelectionSet)

	require.Contains(t, names, "viewer", "query must select viewer")
	require.Contains(t, names, "zoneTag", "query must select zoneTag")
	require.Contains(t, names, "httpRequestsAdaptiveGroups", "query must select httpRequestsAdaptiveGroups")
	require.Contains(t, names, "dimensions", "query must select dimensions")
	require.Contains(t, names, "sum", "query must select sum")
	require.Contains(t, names, "count", "query must select count")
	require.Contains(t, names, "datetime", "query must select datetime")
	require.Contains(t, names, "edgeResponseStatus", "query must select edgeResponseStatus")
	require.Contains(t, names, "clientCountryName", "query must select clientCountryName")
}

func TestBuildGraphQLQuery_RequestSourceEyeball(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	assert.Contains(t, q, `requestSource: "eyeball"`,
		"query must filter to eyeball traffic only")
}

func TestBuildGraphQLQuery_Dataset(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	assert.Contains(t, q, "httpRequestsAdaptiveGroups",
		"query must use the httpRequestsAdaptiveGroups dataset")
}

func TestBuildGraphQLQuery_TimeRange(t *testing.T) {
	t.Parallel()

	q := buildGraphQLQuery("zones", "clientRequestHTTPMethodName", fixedStart, fixedEnd, nil)
	assert.Contains(t, q, fixedStart.Format(time.RFC3339Nano), "start time must appear in query filter")
	assert.Contains(t, q, fixedEnd.Format(time.RFC3339Nano), "end time must appear in query filter")
}
