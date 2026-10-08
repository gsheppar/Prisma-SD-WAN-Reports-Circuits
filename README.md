# Incident & Tunnel Down Analysis

Tools for querying and analyzing Prisma SD-WAN incidents, DI down events, path metrics, and DHCP relay configuration.

---

## Prerequisites

- Python 3.10+
- `prisma_sase` SDK installed:
  ```bash
  pip install prisma-sase
  ```
- A `prismasase_settings.py` file in the same directory with your credentials:
  ```python
  PRISMASASE_CLIENT_ID     = "your-client-id"
  PRISMASASE_CLIENT_SECRET = "your-client-secret"
  PRISMASASE_TSG_ID        = "your-tsg-id"
  ```

---

## query.py — Combined Query Tool

Runs one or all of three queries against the Prisma SASE tenant. Logs in once and shares the session across all queries when running `all`.

### Queries

| Name | What it pulls | Default alarm code |
|------|---------------|--------------------|
| `di-down` | Direct internet down alarms, with circuit label resolution | `NETWORK_DIRECTINTERNET_DOWN` |
| `incidents` | Interface down alarms filtered to `_SL` interfaces | `DEVICEHW_INTERFACE_DOWN` |
| `path-metrics` | CloudFlare DNS ICMP probe latency, packet loss, and jitter for branch sites | — |

### Usage

```bash
# Run all three queries (last 7 days, default)
python query.py

# Run a single query
python query.py --run di-down
python query.py --run incidents
python query.py --run path-metrics

# Specify the time window
python query.py --run di-down --days 3
python query.py --run incidents --hours 24
python query.py --run path-metrics --hours 12
python query.py --run all --days 7

# Custom start/end (ISO 8601 UTC)
python query.py --run di-down --start 2026-09-30T00:00:00Z --end 2026-10-07T00:00:00Z
```

### All options

```
--run {di-down,incidents,path-metrics,all}
                        Which query to run (default: all)

Time range (shared):
  --hours N             Lookback in hours from now (overrides --days/--start/--end)
  --days N              Lookback in days from now (overrides --start/--end)
  --start ISO           Start time in ISO 8601 UTC (default: 7 days ago)
  --end ISO             End time in ISO 8601 UTC (default: now)

Alarm query options:
  --count N             API page size for alarm queries (default: 25)
  --di-code CODE        Alarm code for di-down (default: NETWORK_DIRECTINTERNET_DOWN)
  --inc-code CODE       Alarm code for incidents (default: DEVICEHW_INTERFACE_DOWN)

Output files:
  --di-output FILE      CSV output for di-down (default: di_down_incidents.csv)
  --inc-output FILE     CSV output for incidents (default: incidents.csv)
  --pm-output FILE      CSV output for path-metrics (default: path_metrics.csv)
```

### Output files

Each query produces two files (path-metrics produces one):

| File | Contents |
|------|----------|
| `di_down_incidents.csv` | One row per DI down alarm with site, element, circuit, and extended state |
| `di_down_incidents_analysis.csv` | Pivot: count of each extended state per site / circuit label |
| `incidents.csv` | One row per interface down alarm (`_SL` interfaces only) |
| `incidents_analysis.csv` | Pivot: count of each extended state per site / circuit label |
| `path_metrics.csv` | Avg and max latency, packet loss, and jitter per branch site / circuit |

### Notes

- **DI down** resolves circuit labels by walking `waninterfaces` and `interfaces` APIs — expect extra API calls proportional to the number of unique sites and elements in the result set.
- **Path metrics** ends the query window 5 minutes before now by default; the Prisma API rejects windows that end at the exact current moment. Adjust with `--end` if needed.
- **Incidents** filters to interfaces whose `info.name` contains `_SL`. Use `--inc-code` to query a different alarm code.
