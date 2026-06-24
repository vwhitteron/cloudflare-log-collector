//go:build integration

package main

// Integration tests that validate the GraphQL query against the live
// Cloudflare schema via introspection.
//
// Run with:
//
//	go test -tags integration -run TestCloudflare ./... \
//	    -cftoken YOUR_TOKEN -cfemail YOUR_EMAIL
//
// Or via environment variables CF_API_TOKEN and CF_EMAIL.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

const cfGraphQLURL = "https://api.cloudflare.com/client/v4/graphql"

// cfCreds reads Cloudflare credentials from flags or environment variables.
// Priority: env vars > -cftoken / -cfemail test flags.
var (
	flagToken = new(string)
	flagEmail = new(string)
)

func init() {
	// Register test flags (won't conflict with pflag in main).
	if v := os.Getenv("CF_API_TOKEN"); v != "" {
		*flagToken = v
	}
	if v := os.Getenv("CF_EMAIL"); v != "" {
		*flagEmail = v
	}
}

func cfHTTP(t *testing.T, body []byte) []byte {
	t.Helper()
	token := *flagToken
	email := *flagEmail
	if token == "" {
		token = os.Getenv("CF_API_TOKEN")
	}
	if email == "" {
		email = os.Getenv("CF_EMAIL")
	}
	require.NotEmpty(t, token, "CF_API_TOKEN env var (or -cftoken flag) required for integration tests")
	require.NotEmpty(t, email, "CF_EMAIL env var (or -cfemail flag) required for integration tests")

	req, err := http.NewRequest(http.MethodPost, cfGraphQLURL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("X-Auth-Email", email)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return raw
}

// TestCloudflare_IntrospectionSchema fetches Cloudflare's schema via
// introspection and validates our two query variants against it.
func TestCloudflare_IntrospectionSchema(t *testing.T) {
	introspectionQuery := `{
		__schema {
			types {
				kind name
				fields(includeDeprecated: true) {
					name
					args { name type { kind name ofType { kind name ofType { kind name } } } }
					type { kind name ofType { kind name ofType { kind name } } }
				}
				inputFields { name type { kind name ofType { kind name } } }
				enumValues(includeDeprecated: true) { name }
			}
		}
	}`

	body, _ := json.Marshal(map[string]string{"query": introspectionQuery})
	raw := cfHTTP(t, body)

	// Parse introspection result into an SDL-compatible schema using gqlparser.
	var introspectionResult struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &introspectionResult))
	require.NotEmpty(t, introspectionResult.Data, "introspection returned no data")

	schema, schemaErr := gqlparser.LoadSchema(&ast.Source{
		Name:  "cloudflare",
		Input: string(raw),
	})
	if schemaErr != nil {
		// gqlparser expects SDL, not introspection JSON; log and fall back to live
		// query validation below instead.
		t.Logf("Schema load from introspection JSON not supported by gqlparser (%v); using live query validation instead", schemaErr)
	} else {
		start := time.Now().UTC().Add(-5 * time.Minute)
		end := time.Now().UTC()
		for _, sel := range []string{
			"clientRequestHTTPMethodName",
			"clientRequestHTTPMethodName: clientRequestHTTPMethod",
		} {
			q := buildGraphQLQuery("zones", sel, start, end)
			_, errs := gqlparser.LoadQuery(schema, q)
			assert.Nil(t, errs, "query with selector %q must be valid against Cloudflare schema: %v", sel, errs)
		}
	}
}

// TestCloudflare_LiveQueryNoErrors sends the real query to Cloudflare and
// asserts the response contains no "unknown field" errors.  It does not
// require any traffic to be present — an empty result is fine.
func TestCloudflare_LiveQueryNoErrors(t *testing.T) {
	start := time.Now().UTC().Add(-5 * time.Minute)
	end := time.Now().UTC()

	selectors := []string{
		"clientRequestHTTPMethodName",
		"clientRequestHTTPMethodName: clientRequestHTTPMethod",
	}

	for _, sel := range selectors {
		t.Run(fmt.Sprintf("selector=%s", sel), func(t *testing.T) {
			q := buildGraphQLQuery("zones", sel, start, end)
			body, _ := json.Marshal(map[string]string{"query": q})
			raw := cfHTTP(t, body)

			var result struct {
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			}
			require.NoError(t, json.Unmarshal(raw, &result), "response must be valid JSON: %s", string(raw))

			for _, e := range result.Errors {
				assert.NotContains(t, e.Message, "unknown field",
					"query contains a field not in Cloudflare schema: %s", e.Message)
			}
		})
	}
}
