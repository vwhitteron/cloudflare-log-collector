# cloudflare-log-collector

A Go daemon that polls Cloudflare's GraphQL Analytics API and forwards HTTP request logs and R2 storage metrics to [OpenObserve](https://openobserve.ai) or [Splunk](https://splunk.com).

## Features

- Polls Cloudflare zone HTTP logs and R2 access logs on a configurable interval
- Forwards to OpenObserve (via HTTP ingest) or Splunk (via HEC)
- Supports multiple zones; auto-discovers all zones if none specified
- Gracefully handles plan-restricted GraphQL fields per zone

## Installation

```sh
go build -o cflog .
cp cflog /usr/local/bin/cflog
```

To install and enable the systemd service:

```sh
cp cflog.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cflog
```

## Configuration

Copy [cflog.conf](cflog.conf) and fill in credentials for your environment:

```ini
poll_interval         = 15m  # accepts Go duration syntax e.g. 30s, 2m

cloudflare_api_token  = <token>
cloudflareemail       = user@example.com
cloudflare_zone_ids   = zone1.example.com,zone2.example.com   # omit for all zones
cloudflare_account_id = <account id>                          # required for R2 logs

# Optional: remove or comment out if not required
openobserve_url       = https://openobserve.exmaple.com/api/default/default/_json
openobserve_user      = cflog@example.com
openobserve_pass      = secret_password

# Optional: remove or comment out if not required
splunk_url            = https://splunk.example.com:8088/services/collector/event
splunk_token          = secret-token
```

## Usage

```sh
cflog --config /usr/local/etc/cflog.conf             # run normally
cflog --config /usr/local/etc/cflog.conf --debug     # verbose logging
cflog --config /usr/local/etc/cflog.conf --simulate  # send synthetic test logs
```

## Requirements

- Cloudflare API token with read access to Zone Analytics, Zone Logs, and Account Analytics
- Go 1.25+
