package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	flag "github.com/spf13/pflag"
)

const (
	defaultPollInterval = 900 * time.Second
	httpClientTimeout   = 30 * time.Second

	// gap-recovery defaults.
	defaultMaxLookback = 72 * time.Hour // Cloudflare adaptive datasets retain ~72h.
	healthCheckTimeout = 5 * time.Second
	stateDirPerm       = 0o755

	// dataset and output identifiers used to key per-output checkpoints.
	datasetHTTP       = "http"
	datasetR2         = "r2"
	outputOpenObserve = "openobserve"
	outputSplunk      = "splunk"

	// simulation constants.
	simMaxCount    = 5
	simMaxBytes    = 4901
	simBytesOffset = 100
	simMaxRequests = 5

	nanosPerSecond   = 1e9
	pageSplitDivisor = 2

	// retry constants for failed fetches.
	maxFetchRetries = 3
	retryBaseDelay  = 5 * time.Second
	retryMaxDelay   = 60 * time.Second

	// methodSelector* constants control which GraphQL field name is used for
	// the HTTP request method dimension. Cloudflare renamed the field across
	// API versions; we probe in order and fall back to omitting it entirely.
	methodSelectorName  = "clientRequestHTTPMethodName"
	methodSelectorAlias = "clientRequestHTTPMethodName: clientRequestHTTPMethod"
	methodSelectorNone  = "(none)" // sentinel: method field not available
)

var (
	errGraphQL      = errors.New("GraphQL error")
	errMalformedURL = errors.New("malformed url")
)

type retryKind int

const (
	retryNone retryKind = iota
	retryNext           // advance to next method selector
	retrySame           // retry same selector after dropping a plan-restricted field
)

type Config struct {
	APIToken        string
	Email           string
	AccountID       string
	ZoneIDs         []string
	OpenObserveURL  string
	OpenObserveUser string
	OpenObservePass string
	SplunkURL       string
	SplunkToken     string
	PollInterval    time.Duration
	StateFile       string
	MaxLookback     time.Duration
	BackfillChunk   time.Duration
}

// collector holds per-run mutable state shared across fetch/send operations.
type collector struct {
	methodSelector string
	zoneNames      map[string]string
	disabledFields map[string]bool
	store          *checkpointStore
	// lastHealthy tracks the last observed health of each output, keyed by output
	// name, so transitions are logged once rather than every tick.
	lastHealthy map[string]bool
}

func newCollector(store *checkpointStore) *collector {
	return &collector{
		zoneNames:      make(map[string]string),
		disabledFields: make(map[string]bool),
		store:          store,
		lastHealthy:    make(map[string]bool),
	}
}

// authzFieldFromError extracts the lowercase field name and zone ID from a Cloudflare
// authorization error like "zone 'ZONEID' does not have access to the field 'fieldname'".
func authzFieldFromError(msg string) (field, zoneID string) {
	const needle = "does not have access to the field '"

	lower := strings.ToLower(msg)
	idx := strings.Index(lower, needle)

	if idx < 0 {
		return "", ""
	}

	rest := msg[idx+len(needle):]
	before, _, ok := strings.Cut(rest, "'")

	if !ok {
		return "", ""
	}

	field = strings.ToLower(before)

	// Extract zone ID from "zone 'ZONEID' does not..."
	const zonePrefix = "zone '"

	if zi := strings.Index(msg[:idx], zonePrefix); zi >= 0 {
		zoneRest := msg[zi+len(zonePrefix):]
		if before0, _, ok0 := strings.Cut(zoneRest, "'"); ok0 {
			zoneID = before0
		}
	}

	return field, zoneID
}

func parseZoneIDs(value string) []string {
	var ids []string

	for z := range strings.SplitSeq(value, ",") {
		if id := strings.TrimSpace(z); id != "" {
			ids = append(ids, id)
		}
	}

	return ids
}

func parsePollInterval(value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid poll_interval %q: %w", value, err)
	}

	return d, nil
}

func applyConfigKey(cfg *Config, key, value string) error {
	stringFields := map[string]*string{
		"cloudflare_api_token":  &cfg.APIToken,
		"cloudflare_email":      &cfg.Email,
		"cloudflare_account_id": &cfg.AccountID,
		"openobserve_url":       &cfg.OpenObserveURL,
		"openobserve_user":      &cfg.OpenObserveUser,
		"openobserve_pass":      &cfg.OpenObservePass,
		"splunk_url":            &cfg.SplunkURL,
		"splunk_token":          &cfg.SplunkToken,
		"state_file":            &cfg.StateFile,
	}

	if ptr, ok := stringFields[key]; ok {
		*ptr = value

		return nil
	}

	switch key {
	case "cloudflare_zone_ids":
		cfg.ZoneIDs = parseZoneIDs(value)
	case "poll_interval":
		var err error

		cfg.PollInterval, err = parsePollInterval(value)

		return err
	case "max_lookback":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid max_lookback %q: %w", value, err)
		}

		cfg.MaxLookback = d
	case "backfill_chunk":
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid backfill_chunk %q: %w", value, err)
		}

		cfg.BackfillChunk = d
	}

	return nil
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open config file %q: %w", path, err)
	}

	defer func() {
		_ = file.Close()
	}()

	cfg := &Config{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		err = applyConfigKey(cfg, strings.TrimSpace(key), strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("error reading config file %q: %w", path, err)
	}

	applyConfigDefaults(cfg)

	return cfg, nil
}

// applyConfigDefaults fills in defaults for any unset configuration values.
func applyConfigDefaults(cfg *Config) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}

	// An unset state_file leaves checkpoints in memory only, which disables
	// gap recovery across restarts (checkpoints are lost on exit).

	if cfg.MaxLookback <= 0 {
		cfg.MaxLookback = defaultMaxLookback
	}

	// Default the backfill chunk to the poll interval: in steady state this is a
	// single window, and it only subdivides when catching up after downtime.
	if cfg.BackfillChunk <= 0 {
		cfg.BackfillChunk = cfg.PollInterval
	}
}

// checkpointStore persists the last successfully-delivered event time for each
// (dataset, output) pair so the collector can resume without gaps after a
// restart. Keys are "<dataset>.<output>", e.g. "http.splunk". A zero path keeps
// state in memory only (useful for tests).
type checkpointStore struct {
	mu          sync.Mutex
	path        string
	checkpoints map[string]time.Time
}

func checkpointKey(dataset, output string) string {
	return dataset + "." + output
}

// loadState reads the state file at path, returning an empty store if the file
// does not exist yet. A corrupt file is a hard error so we don't silently reset
// checkpoints and re-ingest history.
func loadState(path string) (*checkpointStore, error) {
	store := &checkpointStore{path: path, checkpoints: make(map[string]time.Time)}

	if path == "" {
		return store, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}

		return nil, fmt.Errorf("read state file %q: %w", path, err)
	}

	if len(data) == 0 {
		return store, nil
	}

	err = json.Unmarshal(data, &store.checkpoints)
	if err != nil {
		return nil, fmt.Errorf("parse state file %q: %w", path, err)
	}

	return store, nil
}

func (s *checkpointStore) get(dataset, output string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.checkpoints[checkpointKey(dataset, output)]
}

// advance moves a checkpoint forward to when and persists. It never regresses a
// checkpoint, so passing an older time is a no-op.
func (s *checkpointStore) advance(dataset, output string, when time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := checkpointKey(dataset, output)
	if !when.After(s.checkpoints[key]) {
		return
	}

	s.checkpoints[key] = when

	err := s.saveLocked()
	if err != nil {
		slog.Error("failed to persist checkpoint", "key", key, "err", err)
	}
}

// saveLocked atomically writes the state file. Caller must hold s.mu.
func (s *checkpointStore) saveLocked() error {
	if s.path == "" {
		return nil
	}

	data, err := json.MarshalIndent(s.checkpoints, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	dir := filepath.Dir(s.path)

	err = os.MkdirAll(dir, stateDirPerm)
	if err != nil {
		return fmt.Errorf("create state dir %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}

	tmpName := tmp.Name()

	_, err = tmp.Write(data)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)

		return fmt.Errorf("write temp state file: %w", err)
	}

	err = tmp.Close()
	if err != nil {
		_ = os.Remove(tmpName)

		return fmt.Errorf("close temp state file: %w", err)
	}

	err = os.Rename(tmpName, s.path)
	if err != nil {
		_ = os.Remove(tmpName)

		return fmt.Errorf("rename state file: %w", err)
	}

	return nil
}

type Dimensions struct {
	ZoneTag                     string `json:"zoneTag"`
	ZoneName                    string `json:"zoneName"`
	Datetime                    string `json:"datetime"`
	ClientRequestHTTPMethodName string `json:"clientRequestHTTPMethodName"`
	ClientRequestHTTPProtocol   string `json:"clientRequestHttpProtocol"`
	ClientRequestURI            string `json:"clientRequestURI"`
	EdgeResponseStatus          int    `json:"edgeResponseStatus"`
	ClientCountryName           string `json:"clientCountryName"`
	CacheStatus                 string `json:"cacheStatus"`
	ColoCode                    string `json:"coloCode"`
	ClientDeviceType            string `json:"clientDeviceType"`
	ClientRefererHost           string `json:"clientRefererHost"`
	ClientASNDescription        string `json:"clientAsnDescription"`
	ClientSSLProtocol           string `json:"clientSslProtocol"`
}

type Sum struct {
	Bytes    int `json:"bytes"`
	Requests int `json:"requests"`
	Visits   int `json:"visits"`
}

type LogEntry struct {
	Dimensions Dimensions `json:"dimensions"`
	Sum        Sum        `json:"sum"`
	Count      int        `json:"count"`
}

type FlatLog struct {
	ZoneTag                     string `json:"zoneTag"`
	ZoneName                    string `json:"zoneName"`
	Datetime                    string `json:"datetime"`
	ClientRequestHTTPMethodName string `json:"clientRequestHTTPMethodName"`
	ClientRequestHTTPProtocol   string `json:"clientRequestHttpProtocol"`
	ClientRequestURI            string `json:"clientRequestURI"`
	EdgeResponseStatus          int    `json:"edgeResponseStatus"`
	ClientCountryName           string `json:"clientCountryName"`
	CacheStatus                 string `json:"cacheStatus"`
	ColoCode                    string `json:"coloCode"`
	ClientDeviceType            string `json:"clientDeviceType"`
	ClientRefererHost           string `json:"clientRefererHost"`
	ClientASNDescription        string `json:"clientAsnDescription"`
	ClientSSLProtocol           string `json:"clientSslProtocol"`
	Bytes                       int    `json:"bytes"`
	Requests                    int    `json:"requests"`
	Visits                      int    `json:"visits"`
}

// R2Dimensions holds the dimension fields for r2StorageAdaptiveGroups.
type R2Dimensions struct {
	Datetime   string `json:"datetime"`
	BucketName string `json:"bucketName"`
}

type R2Max struct {
	Bytes        int `json:"bytes"`
	ObjectCount  int `json:"objectCount"`
	MetadataSize int `json:"metadataSize"`
}

type R2LogEntry struct {
	Dimensions R2Dimensions `json:"dimensions"`
	Max        R2Max        `json:"max"`
}

type R2FlatLog struct {
	Datetime     string `json:"datetime"`
	BucketName   string `json:"bucketName"`
	Bytes        int    `json:"bytes"`
	ObjectCount  int    `json:"objectCount"`
	MetadataSize int    `json:"metadataSize"`
}

//nolint:gosec // simulation data; cryptographic randomness not required
func randFrom(s []string) string {
	return s[rand.Intn(len(s))]
}

//nolint:gosec // simulation data; cryptographic randomness not required
func simulateCloudFlareLogs() []LogEntry {
	methods := []string{"GET", "POST", "PUT"}
	uris := []string{"/", "/api/users", "/checkout"}
	statuses := []int{200, 404, 429, 503}
	countries := []string{"US", "IN", "UK"}
	protocols := []string{"HTTP/1.1", "HTTP/2", "HTTP/3"}
	cacheStatuses := []string{"hit", "miss", "expired", "bypass"}
	colos := []string{"SYD", "LAX", "LHR", "SIN"}
	devices := []string{"desktop", "mobile", "tablet"}
	referers := []string{"", "example.com", "google.com"}
	asns := []string{"CLOUDFLARENET", "AMAZON-02", "GOOGLE"}
	sslProtocols := []string{"TLSv1.2", "TLSv1.3", "none"}

	count := rand.Intn(simMaxCount) + 1

	logs := make([]LogEntry, count)
	for idx := range logs {
		simBytes := rand.Intn(simMaxBytes) + simBytesOffset
		simRequests := rand.Intn(simMaxRequests) + 1
		logs[idx] = LogEntry{
			Dimensions: Dimensions{
				ZoneTag:                     "simulated-zone",
				ZoneName:                    "simulated",
				Datetime:                    time.Now().UTC().Format(time.RFC3339Nano),
				ClientRequestHTTPMethodName: randFrom(methods),
				ClientRequestHTTPProtocol:   randFrom(protocols),
				ClientRequestURI:            randFrom(uris),
				EdgeResponseStatus:          statuses[rand.Intn(len(statuses))],
				ClientCountryName:           randFrom(countries),
				CacheStatus:                 randFrom(cacheStatuses),
				ColoCode:                    randFrom(colos),
				ClientDeviceType:            randFrom(devices),
				ClientRefererHost:           randFrom(referers),
				ClientASNDescription:        randFrom(asns),
				ClientSSLProtocol:           randFrom(sslProtocols),
			},
			Sum: Sum{
				Bytes:    simBytes,
				Requests: simRequests,
				Visits:   rand.Intn(simRequests + 1),
			},
		}
	}

	return logs
}

//nolint:gosec // simulation data; cryptographic randomness not required
func simulateR2Logs() []R2LogEntry {
	buckets := []string{"my-bucket", "backups", "assets"}

	count := rand.Intn(simMaxCount) + 1

	logs := make([]R2LogEntry, count)
	for idx := range logs {
		simBytes := rand.Intn(simMaxBytes) + simBytesOffset
		logs[idx] = R2LogEntry{
			Dimensions: R2Dimensions{
				Datetime:   time.Now().UTC().Format(time.RFC3339Nano),
				BucketName: randFrom(buckets),
			},
			Max: R2Max{
				Bytes: simBytes,
			},
		}
	}

	return logs
}

// buildZonesCall returns the zones(...) fragment for use in a GraphQL query.
func buildZonesCall(zoneIDs []string) string {
	if len(zoneIDs) == 1 {
		return fmt.Sprintf(`zones(filter: {zoneTag: "%s"})`, zoneIDs[0])
	}

	if len(zoneIDs) > 1 {
		quoted := make([]string, len(zoneIDs))
		for i, id := range zoneIDs {
			quoted[i] = fmt.Sprintf("\"%s\"", id)
		}

		return fmt.Sprintf(`zones(filter: {zoneTag_in: [%s]})`, strings.Join(quoted, ", "))
	}

	return "zones"
}

// buildOptionalDimensions returns the indented GraphQL lines for plan-restricted
// dimension fields, omitting any that are in disabledFields.
func buildOptionalDimensions(disabledFields map[string]bool) string {
	type dimField struct{ alias, expr string }

	optional := []dimField{
		{"colocode", "coloCode"},
		{"clientdevicetype", "clientDeviceType"},
		{"clientrefererhost", "clientRefererHost"},
		{"clientasndescription", "clientAsnDescription: clientASNDescription"},
		{"clientsslprotocol", "clientSslProtocol: clientSSLProtocol"},
	}

	var lines []string

	for _, dim := range optional {
		if !disabledFields[dim.alias] {
			lines = append(lines, "          "+dim.expr)
		}
	}

	return strings.Join(lines, "\n")
}

// buildGraphQLQuery returns the full GraphQL query string for the given parameters.
func buildGraphQLQuery(zonesCall, methodSelector string, startTime, endTime time.Time, disabledFields map[string]bool) string {
	const tmplText = `{
  viewer {
    {{.ZonesCall}} {
      zoneTag
      httpRequestsAdaptiveGroups(limit: 1000, filter: {datetime_geq: "{{.Start}}", datetime_leq: "{{.End}}", requestSource: "eyeball"}) {
        count
        dimensions {
          datetime
          {{.MethodSelector}}
          clientRequestHttpProtocol: clientRequestHTTPProtocol
          clientRequestURI: clientRequestPath
          edgeResponseStatus
          clientCountryName
          cacheStatus
{{.OptionalDimensions}}
        }
        sum {
          bytes: edgeResponseBytes
          visits
        }
      }
    }
  }
}`

	var buf bytes.Buffer

	methodSel := methodSelector
	if methodSel == methodSelectorNone {
		methodSel = ""
	}

	err := template.Must(template.New("cfgql").Parse(tmplText)).Execute(&buf, map[string]string{
		"ZonesCall":          zonesCall,
		"MethodSelector":     methodSel,
		"Start":              startTime.Format(time.RFC3339Nano),
		"End":                endTime.Format(time.RFC3339Nano),
		"OptionalDimensions": buildOptionalDimensions(disabledFields),
	})
	if err != nil {
		panic(fmt.Sprintf("buildGraphQLQuery: template execution failed: %v", err))
	}

	return buf.String()
}

type graphQLResponse struct {
	Data struct {
		Viewer struct {
			Zones []struct {
				ZoneTag                    string     `json:"zoneTag"`
				HTTPRequestsAdaptiveGroups []LogEntry `json:"httpRequestsAdaptiveGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// buildR2GraphQLQuery returns the GraphQL query for r2StorageAdaptiveGroups.
// R2 analytics are queried at the account level, not the zone level.
func buildR2GraphQLQuery(accountID string, startTime, endTime time.Time) string {
	const tmplText = `{
  viewer {
    accounts(filter: {accountTag: "{{.AccountID}}"}) {
      r2StorageAdaptiveGroups(limit: 1000, filter: {datetime_geq: "{{.Start}}", datetime_leq: "{{.End}}"}) {
        dimensions {
          datetime
          bucketName
        }
        max {
          bytes: payloadSize
          objectCount
          metadataSize

        }
      }
    }
  }
}`

	var buf bytes.Buffer

	err := template.Must(template.New("r2gql").Parse(tmplText)).Execute(&buf, map[string]string{
		"AccountID": accountID,
		"Start":     startTime.Format(time.RFC3339Nano),
		"End":       endTime.Format(time.RFC3339Nano),
	})
	if err != nil {
		panic(fmt.Sprintf("buildR2GraphQLQuery: template execution failed: %v", err))
	}

	return buf.String()
}

type r2GraphQLResponse struct {
	Data struct {
		Viewer struct {
			Accounts []struct {
				R2StorageAdaptiveGroups []R2LogEntry `json:"r2StorageAdaptiveGroups"`
			} `json:"accounts"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func doGraphQLRequest(ctx context.Context, client *http.Client, cfg *Config, query string) ([]byte, int, error) {
	const cfURL = "https://api.cloudflare.com/client/v4/graphql"

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, 0, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Auth-Email", cfg.Email)
	req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("do request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

func buildMethodSelectors(cached string) []string {
	switch cached {
	case "", methodSelectorName:
		// Not yet determined, or last-known was the primary name: probe all three.
		return []string{methodSelectorName, methodSelectorAlias, methodSelectorNone}
	case methodSelectorNone:
		// Method field confirmed unavailable; skip it.
		return []string{methodSelectorNone}
	default:
		// cached is the alias (or some future value): try it first, then fall back to name.
		return []string{cached, methodSelectorName}
	}
}

// processError classifies a GraphQL error and updates collector state.
// Returns the retry action and any fatal error.
func (c *collector) processError(msg, selector string, selectors []string, attempt int) (retryKind, error) {
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "unknown field") {
		if selector == c.methodSelector {
			c.methodSelector = ""
		}

		if attempt < len(selectors)-1 {
			return retryNext, nil
		}

		return retryNone, fmt.Errorf("%w: %s", errGraphQL, msg)
	}

	if strings.Contains(lower, "does not have access to the field") {
		if field, zoneID := authzFieldFromError(msg); field != "" {
			c.disabledFields[field] = true
			slog.Warn("dropping plan-restricted field", "field", field, "zone", zoneID)

			return retrySame, nil
		}
	}

	return retryNone, fmt.Errorf("%w: %s", errGraphQL, msg)
}

// processGraphQLAttempt parses a response body and extracts log entries.
func (c *collector) processGraphQLAttempt(body []byte, selector string, selectors []string, attempt int) ([]LogEntry, retryKind, error) {
	var result graphQLResponse

	err := json.Unmarshal(body, &result)
	if err != nil {
		return nil, retryNone, fmt.Errorf("parse response: %w", err)
	}

	if len(result.Errors) > 0 {
		action, err := c.processError(result.Errors[0].Message, selector, selectors, attempt)

		return nil, action, err
	}

	if len(result.Data.Viewer.Zones) == 0 {
		slog.Debug("no logs yet, waiting for traffic")

		return nil, retryNone, nil
	}

	var logs []LogEntry

	for _, zone := range result.Data.Viewer.Zones {
		for _, entry := range zone.HTTPRequestsAdaptiveGroups {
			entry.Dimensions.ZoneTag = zone.ZoneTag
			entry.Dimensions.ZoneName = c.zoneNames[zone.ZoneTag]
			entry.Sum.Requests = entry.Count
			logs = append(logs, entry)
		}
	}

	return logs, retryNone, nil
}

// processR2Attempt parses an R2 response body and extracts log entries.
// processR2Attempt parses an R2 response body and extracts log entries.
func (c *collector) processR2Attempt(body []byte) ([]R2LogEntry, error) {
	var result r2GraphQLResponse

	err := json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("parse R2 response: %w", err)
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("%w: %s", errGraphQL, result.Errors[0].Message)
	}

	if len(result.Data.Viewer.Accounts) == 0 {
		slog.Debug("no R2 accounts found")

		return nil, nil
	}

	var logs []R2LogEntry

	for _, account := range result.Data.Viewer.Accounts {
		logs = append(logs, account.R2StorageAdaptiveGroups...)
	}

	if len(logs) == 0 {
		slog.Debug("no R2 logs yet, waiting for traffic")

		return nil, nil
	}

	return logs, nil
}

// fetchR2WithPagination fetches R2 logs for [startTime, endTime], recursively splitting
// the window when the API returns 1000 rows (the limit).
func (c *collector) fetchR2WithPagination(ctx context.Context, client *http.Client, cfg *Config,
	startTime, endTime time.Time, depth int,
) ([]R2LogEntry, bool) {
	query := buildR2GraphQLQuery(cfg.AccountID, startTime, endTime)

	body, status, err := doGraphQLRequest(ctx, client, cfg, query)
	if err != nil {
		slog.Error("Cloudflare R2 request failed", "err", err)

		return nil, true // transient failure
	}

	slog.Debug("Cloudflare R2 GraphQL response", "body", string(body))

	if status != http.StatusOK {
		slog.Error("Cloudflare R2 API error", "status", status, "body", string(body))

		return nil, true // transient failure
	}

	logs, err := c.processR2Attempt(body)
	if err != nil {
		slog.Error("process R2 response failed", "err", err)

		return nil, true // transient failure
	}

	// Check if we hit the 1000-row limit — if so, split the window and paginate.
	if len(logs) == 1000 && depth < maxPageDepth {
		slog.Info("hit 1000-row limit for R2, splitting time window", "depth", depth, "start", startTime, "end", endTime)
		mid := startTime.Add(endTime.Sub(startTime) / pageSplitDivisor)

		half1, failed1 := c.fetchR2WithPagination(ctx, client, cfg, startTime, mid, depth+1)
		half2, failed2 := c.fetchR2WithPagination(ctx, client, cfg, mid, endTime, depth+1)

		if failed1 || failed2 {
			return nil, true
		}

		result := make([]R2LogEntry, 0, len(half1)+len(half2))
		result = append(result, half1...)
		result = append(result, half2...)

		return result, false
	}

	return logs, false
}

// fetchR2Window fetches R2 logs for [startTime, endTime], retrying transient
// failures. ok is false only when fetching ultimately failed, signalling the
// caller not to advance any checkpoint.
func (c *collector) fetchR2Window(ctx context.Context, cfg *Config, startTime, endTime time.Time) (entries []R2LogEntry, succeeded bool) {
	client := &http.Client{Timeout: httpClientTimeout}

	// Retry with exponential backoff for transient failures.
	for retry := 0; retry <= maxFetchRetries; retry++ {
		if retry > 0 {
			delay := min(
				// 5s, 10s, 20s
				retryBaseDelay*(1<<uint(retry-1)), retryMaxDelay) //nolint:gosec // retry>0 so retry-1>=0

			slog.Info("retrying Cloudflare R2 fetch", "retry", retry, "delay", delay, "start", startTime, "end", endTime)
			time.Sleep(delay)
		}

		logs, fetchFailed := c.fetchR2WithPagination(ctx, client, cfg, startTime, endTime, 0)

		if fetchFailed {
			// Transient error — retry if we have retries left.
			if retry == maxFetchRetries {
				slog.Error("exhausted all retries for Cloudflare R2 fetch", "start", startTime, "end", endTime)

				return nil, false
			}

			continue
		}

		// Success (or graceful degradation).
		return logs, true
	}

	// Should not reach here, but just in case.
	slog.Error("fetchR2Window exited unexpectedly")

	return nil, false
}

// windowStart returns the lower bound of the fetch window: the oldest checkpoint
// across the given outputs, clamped to now-MaxLookback. A zero checkpoint (never
// delivered) means start one poll interval back, as before. now and the result
// are UTC.
func (c *collector) windowStart(dataset string, outputs []string, now time.Time, cfg *Config) time.Time {
	oldest := now

	for _, out := range outputs {
		checkpoint := c.store.get(dataset, out)
		if checkpoint.IsZero() {
			checkpoint = now.Add(-cfg.PollInterval)
		}

		if checkpoint.Before(oldest) {
			oldest = checkpoint
		}
	}

	if limit := now.Add(-cfg.MaxLookback); oldest.Before(limit) {
		slog.Warn("backfill window exceeds max_lookback, clamping",
			"dataset", dataset, "requested_start", oldest, "clamped_start", limit, "max_lookback", cfg.MaxLookback)

		oldest = limit
	}

	return oldest
}

// chunkBounds splits [start, end] into successive [chunkStart, chunkEnd] windows
// no longer than chunk. In steady state this yields a single window; it only
// subdivides when backfilling a gap after downtime.
func chunkBounds(start, end time.Time, chunk time.Duration) [][2]time.Time {
	if chunk <= 0 {
		return [][2]time.Time{{start, end}}
	}

	var bounds [][2]time.Time

	for cur := start; cur.Before(end); {
		next := cur.Add(chunk)
		if next.After(end) {
			next = end
		}

		bounds = append(bounds, [2]time.Time{cur, next})
		cur = next
	}

	return bounds
}

func (c *collector) recordMethodSelector(selector string) {
	c.methodSelector = selector

	if selector == methodSelectorNone {
		slog.Warn("HTTP method field unavailable in Cloudflare schema, collecting without it")
	} else {
		slog.Debug("using method selector", "selector", c.methodSelector)
	}
}

// maxPageDepth limits recursion when splitting time windows for pagination.
const maxPageDepth = 8

// fetchHTTPWindow fetches HTTP request logs for [startTime, endTime], retrying
// transient failures. ok is false only when fetching ultimately failed,
// signalling the caller not to advance any checkpoint.
func (c *collector) fetchHTTPWindow(ctx context.Context, cfg *Config, startTime, endTime time.Time) (entries []LogEntry, succeeded bool) {
	zonesCall := buildZonesCall(cfg.ZoneIDs)
	selectors := buildMethodSelectors(c.methodSelector)
	client := &http.Client{Timeout: httpClientTimeout}

	// Retry with exponential backoff for transient failures.
	for retry := 0; retry <= maxFetchRetries; retry++ {
		if retry > 0 {
			delay := min(
				// 5s, 10s, 20s
				retryBaseDelay*(1<<uint(retry-1)), retryMaxDelay) //nolint:gosec // retry>0 so retry-1>=0

			slog.Info("retrying Cloudflare fetch", "retry", retry, "delay", delay, "start", startTime, "end", endTime)
			time.Sleep(delay)
		}

		logs, fetchFailed := c.fetchWithPagination(ctx, client, cfg, zonesCall, selectors, startTime, endTime, 0)

		if fetchFailed {
			// Transient error — retry if we have retries left.
			if retry == maxFetchRetries {
				slog.Error("exhausted all retries for Cloudflare fetch", "start", startTime, "end", endTime)

				return nil, false
			}

			continue
		}

		// Success (or graceful degradation).
		return logs, true
	}

	// Should not reach here, but just in case.
	slog.Error("fetchHTTPWindow exited unexpectedly")

	return nil, false
}

// fetchWithPagination fetches logs for [startTime, endTime], recursively splitting
// the window when the API returns 1000 rows (the limit). depth guards against
// infinite recursion on extremely high-cardinality windows.
func (c *collector) fetchWithPagination(ctx context.Context, client *http.Client, cfg *Config,
	zonesCall string, selectors []string, startTime, endTime time.Time, depth int,
) ([]LogEntry, bool) {
	attempt := 0
	for attempt < len(selectors) {
		selector := selectors[attempt]
		query := buildGraphQLQuery(zonesCall, selector, startTime, endTime, c.disabledFields)

		body, status, err := doGraphQLRequest(ctx, client, cfg, query)
		if err != nil {
			slog.Error("Cloudflare request failed", "err", err)

			return nil, true // transient failure
		}

		slog.Debug("Cloudflare GraphQL response", "attempt", attempt+1, "body", string(body))

		if status != http.StatusOK {
			slog.Error("Cloudflare API error", "status", status, "body", string(body))

			return nil, true // transient failure
		}

		logs, action, err := c.processGraphQLAttempt(body, selector, selectors, attempt)
		if err != nil {
			slog.Error("process response failed", "err", err)

			return nil, true // transient failure
		}

		if action == retryNext {
			attempt++

			continue
		}

		if action == retrySame {
			continue
		}

		if c.methodSelector == "" {
			c.recordMethodSelector(selector)
		}

		if len(logs) == 1000 && depth < maxPageDepth {
			return c.splitFetchWindow(ctx, client, cfg, zonesCall, selectors, startTime, endTime, depth)
		}

		return logs, false
	}

	// No compatible selector found.
	slog.Error("no compatible HTTP method field found in Cloudflare schema")

	return nil, false // not a transient failure
}

// splitFetchWindow splits [startTime, endTime] at the midpoint and fetches each half,
// used when a fetch returns the 1000-row API limit.
func (c *collector) splitFetchWindow(ctx context.Context, client *http.Client, cfg *Config,
	zonesCall string, selectors []string, startTime, endTime time.Time, depth int,
) ([]LogEntry, bool) {
	slog.Info("hit 1000-row limit, splitting time window", "depth", depth, "start", startTime, "end", endTime)
	mid := startTime.Add(endTime.Sub(startTime) / pageSplitDivisor)

	half1, failed1 := c.fetchWithPagination(ctx, client, cfg, zonesCall, selectors, startTime, mid, depth+1)
	half2, failed2 := c.fetchWithPagination(ctx, client, cfg, zonesCall, selectors, mid, endTime, depth+1)

	if failed1 || failed2 {
		return nil, true
	}

	result := make([]LogEntry, 0, len(half1)+len(half2))
	result = append(result, half1...)
	result = append(result, half2...)

	return result, false
}

func unixFloatSeconds(t time.Time) float64 {
	return float64(t.UnixNano()) / nanosPerSecond
}

func flattenLogEntry(entry LogEntry) FlatLog {
	return FlatLog{
		ZoneTag:                     entry.Dimensions.ZoneTag,
		ZoneName:                    entry.Dimensions.ZoneName,
		Datetime:                    entry.Dimensions.Datetime,
		ClientRequestHTTPMethodName: entry.Dimensions.ClientRequestHTTPMethodName,
		ClientRequestHTTPProtocol:   entry.Dimensions.ClientRequestHTTPProtocol,
		ClientRequestURI:            entry.Dimensions.ClientRequestURI,
		EdgeResponseStatus:          entry.Dimensions.EdgeResponseStatus,
		ClientCountryName:           entry.Dimensions.ClientCountryName,
		CacheStatus:                 entry.Dimensions.CacheStatus,
		ColoCode:                    entry.Dimensions.ColoCode,
		ClientDeviceType:            entry.Dimensions.ClientDeviceType,
		ClientRefererHost:           entry.Dimensions.ClientRefererHost,
		ClientASNDescription:        entry.Dimensions.ClientASNDescription,
		ClientSSLProtocol:           entry.Dimensions.ClientSSLProtocol,
		Bytes:                       entry.Sum.Bytes,
		Requests:                    entry.Sum.Requests,
		Visits:                      entry.Sum.Visits,
	}
}

func flattenR2LogEntry(entry R2LogEntry) R2FlatLog {
	return R2FlatLog{
		Datetime:     entry.Dimensions.Datetime,
		BucketName:   entry.Dimensions.BucketName,
		Bytes:        entry.Max.Bytes,
		ObjectCount:  entry.Max.ObjectCount,
		MetadataSize: entry.Max.MetadataSize,
	}
}

func doOpenObserveRequest(ctx context.Context, cfg *Config, body []byte) (int, error) {
	authStr := base64.StdEncoding.EncodeToString([]byte(cfg.OpenObserveUser + ":" + cfg.OpenObservePass))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.OpenObserveURL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("create OpenObserve request: %w", err)
	}

	req.Header.Set("Authorization", "Basic "+authStr)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: httpClientTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("openObserve request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, nil
}

// sendToOpenObserve delivers logs and reports whether delivery succeeded. An
// empty batch is a success (nothing to send for this window), so the caller
// advances the checkpoint past an empty window.
func (c *collector) sendToOpenObserve(ctx context.Context, cfg *Config, logs []LogEntry) bool {
	if len(logs) == 0 {
		return true
	}

	payload := make([]FlatLog, len(logs))
	for i, entry := range logs {
		payload[i] = flattenLogEntry(entry)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal payload", "err", err)

		return false
	}

	status, err := doOpenObserveRequest(ctx, cfg, body)
	if err != nil {
		slog.Error("OpenObserve request error", "err", err)

		return false
	}

	if status < 200 || status >= 300 {
		slog.Info("OpenObserve request failed", "count", len(payload), "status", status)

		return false
	}

	slog.Debug("sent logs to OpenObserve", "count", len(payload), "status", status)

	return true
}

func buildSplunkPayload(logs []LogEntry) (bytes.Buffer, error) {
	var buf bytes.Buffer

	for _, entry := range logs {
		flat := flattenLogEntry(entry)

		var eventTime float64

		t, err := time.Parse(time.RFC3339Nano, flat.Datetime)
		if err == nil {
			eventTime = unixFloatSeconds(t)
		}

		envelope := struct {
			Time       float64 `json:"time,omitempty"`
			Event      FlatLog `json:"event"`
			Sourcetype string  `json:"sourcetype"`
		}{
			Time:       eventTime,
			Event:      flat,
			Sourcetype: "_json",
		}

		line, err := json.Marshal(envelope)
		if err != nil {
			return buf, fmt.Errorf("marshal Splunk event: %w", err)
		}

		buf.Write(line)
		buf.WriteByte('\n')
	}

	return buf, nil
}

func doSplunkRequest(ctx context.Context, cfg *Config, buf *bytes.Buffer) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.SplunkURL, buf)
	if err != nil {
		return 0, fmt.Errorf("create Splunk request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+cfg.SplunkToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: httpClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Splunk often uses self-signed certs
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("splunk request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, nil
}

func (c *collector) sendToSplunk(ctx context.Context, cfg *Config, logs []LogEntry) bool {
	if len(logs) == 0 {
		return true
	}

	buf, err := buildSplunkPayload(logs)
	if err != nil {
		slog.Error("failed to build Splunk payload", "err", err)

		return false
	}

	status, err := doSplunkRequest(ctx, cfg, &buf)
	if err != nil {
		slog.Error("Splunk request error", "err", err)

		return false
	}

	if status < 200 || status >= 300 {
		slog.Info("Splunk request failed", "count", len(logs), "status", status)

		return false
	}

	slog.Debug("sent logs to Splunk", "count", len(logs), "status", status)

	return true
}

func (c *collector) sendR2ToOpenObserve(ctx context.Context, cfg *Config, logs []R2LogEntry) bool {
	if len(logs) == 0 {
		return true
	}

	payload := make([]R2FlatLog, len(logs))
	for i, entry := range logs {
		payload[i] = flattenR2LogEntry(entry)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("failed to marshal R2 payload", "err", err)

		return false
	}

	status, err := doOpenObserveRequest(ctx, cfg, body)
	if err != nil {
		slog.Error("OpenObserve R2 request error", "err", err)

		return false
	}

	if status < 200 || status >= 300 {
		slog.Info("OpenObserve R2 request failed", "count", len(payload), "status", status)

		return false
	}

	slog.Debug("sent R2 logs to OpenObserve", "count", len(payload), "status", status)

	return true
}

func buildR2SplunkPayload(logs []R2LogEntry) (bytes.Buffer, error) {
	var buf bytes.Buffer

	for _, entry := range logs {
		flat := flattenR2LogEntry(entry)

		var eventTime float64

		t, err := time.Parse(time.RFC3339Nano, flat.Datetime)
		if err == nil {
			eventTime = unixFloatSeconds(t)
		}

		envelope := struct {
			Time       float64   `json:"time,omitempty"`
			Event      R2FlatLog `json:"event"`
			Sourcetype string    `json:"sourcetype"`
		}{
			Time:       eventTime,
			Event:      flat,
			Sourcetype: "_json",
		}

		line, err := json.Marshal(envelope)
		if err != nil {
			return buf, fmt.Errorf("marshal R2 Splunk event: %w", err)
		}

		buf.Write(line)
		buf.WriteByte('\n')
	}

	return buf, nil
}

func (c *collector) sendR2ToSplunk(ctx context.Context, cfg *Config, logs []R2LogEntry) bool {
	if len(logs) == 0 {
		return true
	}

	buf, err := buildR2SplunkPayload(logs)
	if err != nil {
		slog.Error("failed to build R2 Splunk payload", "err", err)

		return false
	}

	status, err := doSplunkRequest(ctx, cfg, &buf)
	if err != nil {
		slog.Error("R2 Splunk request error", "err", err)

		return false
	}

	if status < 200 || status >= 300 {
		slog.Info("R2 Splunk request failed", "count", len(logs), "status", status)

		return false
	}

	slog.Debug("sent R2 logs to Splunk", "count", len(logs), "status", status)

	return true
}

// enabledOutputs returns the configured destinations, in a stable order.
func enabledOutputs(cfg *Config) []string {
	var outputs []string

	if cfg.OpenObserveURL != "" && cfg.OpenObserveUser != "" {
		outputs = append(outputs, outputOpenObserve)
	}

	if cfg.SplunkURL != "" && cfg.SplunkToken != "" {
		outputs = append(outputs, outputSplunk)
	}

	return outputs
}

// healthBaseURL returns scheme://host[:port] for raw, used to build probe URLs
// from an ingest endpoint that includes a path.
func healthBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", raw, err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: %q", errMalformedURL, raw)
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}

// probe issues a short-timeout GET and reports whether the endpoint answered
// with a 2xx status. setup may set auth headers / transport.
func probe(ctx context.Context, rawURL string, setup func(*http.Request, *http.Client)) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}

	client := &http.Client{Timeout: healthCheckTimeout}

	if setup != nil {
		setup(req, client)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// outputHealthy probes a single destination's health endpoint. There is no point
// fetching (and certainly not backfilling) for a destination we cannot reach.
func outputHealthy(ctx context.Context, cfg *Config, output string) bool {
	switch output {
	case outputOpenObserve:
		base, err := healthBaseURL(cfg.OpenObserveURL)
		if err != nil {
			slog.Debug("cannot derive OpenObserve health URL", "err", err)

			return false
		}

		return probe(ctx, base+"/healthz", func(req *http.Request, _ *http.Client) {
			authStr := base64.StdEncoding.EncodeToString([]byte(cfg.OpenObserveUser + ":" + cfg.OpenObservePass))
			req.Header.Set("Authorization", "Basic "+authStr)
		})
	case outputSplunk:
		base, err := healthBaseURL(cfg.SplunkURL)
		if err != nil {
			slog.Debug("cannot derive Splunk health URL", "err", err)

			return false
		}

		return probe(ctx, base+"/services/collector/health", func(req *http.Request, client *http.Client) {
			req.Header.Set("Authorization", "Splunk "+cfg.SplunkToken)

			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Splunk often uses self-signed certs
			}
		})
	default:
		return false
	}
}

// healthyOutputs probes each output and returns those currently reachable,
// logging health transitions once rather than every tick.
func (c *collector) healthyOutputs(ctx context.Context, cfg *Config, outputs []string) []string {
	var healthy []string

	for _, out := range outputs {
		reachable := outputHealthy(ctx, cfg, out)

		if prev, seen := c.lastHealthy[out]; !seen || prev != reachable {
			if reachable {
				slog.Info("output healthy", "output", out)
			} else {
				slog.Warn("output unhealthy, skipping until reachable", "output", out)
			}
		}

		c.lastHealthy[out] = reachable

		if reachable {
			healthy = append(healthy, out)
		}
	}

	return healthy
}

// afterCheckpoint returns the entries whose RFC3339Nano timestamp (from getTime)
// is strictly after checkpoint. A zero checkpoint keeps everything. Strict
// comparison dedupes events lying exactly on a chunk boundary already delivered
// in the prior chunk.
func afterCheckpoint[T any](entries []T, checkpoint time.Time, getTime func(T) string) []T {
	if checkpoint.IsZero() {
		return entries
	}

	var out []T

	for _, entry := range entries {
		when, err := time.Parse(time.RFC3339Nano, getTime(entry))
		if err != nil {
			// Keep entries with unparseable timestamps rather than drop data.
			out = append(out, entry)

			continue
		}

		if when.After(checkpoint) {
			out = append(out, entry)
		}
	}

	return out
}

// processHTTP fetches and delivers HTTP request logs for the current tick,
// gating on per-output health and advancing each output's checkpoint only on
// confirmed delivery.
func (c *collector) processHTTP(ctx context.Context, cfg *Config, simulate bool) {
	outputs := enabledOutputs(cfg)
	if len(outputs) == 0 {
		return
	}

	// Probe outputs for observability only. The probe targets a secondary health
	// endpoint distinct from the ingest path, so a probe failure is a weak signal;
	// gating ingest on it can suppress delivery to an output that accepts writes
	// fine. Delivery success is the authoritative signal and the only thing that
	// advances a checkpoint, so attempt every enabled output and let failed
	// deliveries simply not advance.
	c.healthyOutputs(ctx, cfg, outputs)

	now := time.Now().UTC()

	if simulate {
		logs := simulateCloudFlareLogs()
		c.deliverHTTP(ctx, cfg, outputs, logs, now)

		return
	}

	start := c.windowStart(datasetHTTP, outputs, now, cfg)

	for _, bound := range chunkBounds(start, now, cfg.BackfillChunk) {
		logs, succeeded := c.fetchHTTPWindow(ctx, cfg, bound[0], bound[1])
		if !succeeded {
			// Leave checkpoints untouched; retry from the same point next tick.
			return
		}

		slog.Info("collected Cloudflare HTTP logs",
			"count", len(logs), "start", bound[0], "end", bound[1])

		c.deliverHTTP(ctx, cfg, outputs, logs, bound[1])
	}
}

// deliverHTTP sends the chunk's logs to each healthy output (filtered to events
// newer than that output's checkpoint) and advances the checkpoint to chunkEnd
// only when delivery succeeds.
func (c *collector) deliverHTTP(ctx context.Context, cfg *Config, healthy []string, logs []LogEntry, chunkEnd time.Time) {
	for _, out := range healthy {
		checkpoint := c.store.get(datasetHTTP, out)
		if !chunkEnd.After(checkpoint) {
			continue // output already past this chunk
		}

		filtered := afterCheckpoint(logs, checkpoint, func(e LogEntry) string { return e.Dimensions.Datetime })

		var delivered bool

		switch out {
		case outputOpenObserve:
			delivered = c.sendToOpenObserve(ctx, cfg, filtered)
		case outputSplunk:
			delivered = c.sendToSplunk(ctx, cfg, filtered)
		}

		if delivered {
			c.store.advance(datasetHTTP, out, chunkEnd)
		}
	}
}

// processR2 mirrors processHTTP for R2 storage logs.
func (c *collector) processR2(ctx context.Context, cfg *Config, simulate bool) {
	if cfg.AccountID == "" {
		slog.Debug("R2 collection skipped: no cloudflare_account_id configured")

		return
	}

	outputs := enabledOutputs(cfg)
	if len(outputs) == 0 {
		return
	}

	// Advisory probe only; deliver to every enabled output. See processHTTP.
	c.healthyOutputs(ctx, cfg, outputs)

	now := time.Now().UTC()

	if simulate {
		c.deliverR2(ctx, cfg, outputs, simulateR2Logs(), now)

		return
	}

	start := c.windowStart(datasetR2, outputs, now, cfg)

	for _, bound := range chunkBounds(start, now, cfg.BackfillChunk) {
		logs, succeeded := c.fetchR2Window(ctx, cfg, bound[0], bound[1])
		if !succeeded {
			return
		}

		slog.Info("collected Cloudflare R2 logs",
			"count", len(logs), "start", bound[0], "end", bound[1])

		c.deliverR2(ctx, cfg, outputs, logs, bound[1])
	}
}

func (c *collector) deliverR2(ctx context.Context, cfg *Config, healthy []string, logs []R2LogEntry, chunkEnd time.Time) {
	for _, out := range healthy {
		checkpoint := c.store.get(datasetR2, out)
		if !chunkEnd.After(checkpoint) {
			continue
		}

		filtered := afterCheckpoint(logs, checkpoint, func(e R2LogEntry) string { return e.Dimensions.Datetime })

		var delivered bool

		switch out {
		case outputOpenObserve:
			delivered = c.sendR2ToOpenObserve(ctx, cfg, filtered)
		case outputSplunk:
			delivered = c.sendR2ToSplunk(ctx, cfg, filtered)
		}

		if delivered {
			c.store.advance(datasetR2, out, chunkEnd)
		}
	}
}

func (c *collector) fetchAllZoneIDs(ctx context.Context, cfg *Config) ([]string, error) {
	client := &http.Client{Timeout: httpClientTimeout}
	page := 1

	var ids []string

	for {
		zonesURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?per_page=50&page=%d", page)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, zonesURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create zones request: %w", err)
		}

		req.Header.Set("X-Auth-Email", cfg.Email)
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("do zones request: %w", err)
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr != nil {
			return nil, fmt.Errorf("read zones response: %w", readErr)
		}

		slog.Debug("Cloudflare zones response", "page", page, "body", string(respBody))

		var result struct {
			Result []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
			ResultInfo struct {
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}

		err = json.Unmarshal(respBody, &result)
		if err != nil {
			return nil, fmt.Errorf("parse zones response: %w", err)
		}

		for _, z := range result.Result {
			ids = append(ids, z.ID)
			c.zoneNames[z.ID] = z.Name
			slog.Debug("discovered zone", "id", z.ID, "name", z.Name)
		}

		if result.ResultInfo.TotalPages <= page || len(result.Result) == 0 {
			break
		}

		page++
	}

	return ids, nil
}

func (c *collector) resolveAndLogZones(ctx context.Context, cfg *Config) {
	if len(cfg.ZoneIDs) == 0 {
		slog.Info("no zone_ids configured, collecting from all zones")

		var err error

		cfg.ZoneIDs, err = c.fetchAllZoneIDs(ctx, cfg)
		if err != nil {
			slog.Warn("could not fetch zone list", "err", err)
		}

		for _, id := range cfg.ZoneIDs {
			slog.Info("collecting zone", "id", id, "name", c.zoneNames[id])
		}

		return
	}

	for _, id := range cfg.ZoneIDs {
		slog.Info("collecting zone", "id", id)
	}
}

// version is the build version, overridable at link time with
// -ldflags "-X main.version=<value>". Defaults to "dev" for local builds.
var version = "dev"

func main() {
	configPath := flag.StringP("config", "c", "/etc/cf2zo.conf", "path to config file")
	simulate := flag.BoolP("simulate", "s", false, "send simulated logs instead of fetching from Cloudflare")
	debug := flag.BoolP("debug", "d", false, "enable debug logging")
	showVersion := flag.BoolP("version", "v", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Println("cflog", version)
		os.Exit(0)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("starting cflog", "version", version)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()

	store, err := loadState(cfg.StateFile)
	if err != nil {
		slog.Error("failed to load state file", "err", err)
		os.Exit(1)
	}

	col := newCollector(store)

	if cfg.StateFile == "" {
		slog.Warn("state_file not set, gap recovery across restarts is disabled")
	}

	slog.Info("streaming Cloudflare logs", "state_file", cfg.StateFile,
		"max_lookback", cfg.MaxLookback, "backfill_chunk", cfg.BackfillChunk)

	if cfg.OpenObserveURL == "" && cfg.SplunkURL == "" {
		slog.Warn("no destinations configured", "hint", "set openobserve_url or splunk_url")
	}

	col.resolveAndLogZones(ctx, cfg)

	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic recovered", "err", r)
				}
			}()

			col.processHTTP(ctx, cfg, *simulate)
			col.processR2(ctx, cfg, *simulate)
		}()
		time.Sleep(cfg.PollInterval)
	}
}
