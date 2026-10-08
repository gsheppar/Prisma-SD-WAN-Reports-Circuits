#!/usr/bin/env python3
"""
Combined Prisma SD-WAN query tool.

Queries:
  di-down       NETWORK_DIRECTINTERNET_DOWN alarms
  incidents     DEVICEHW_INTERFACE_DOWN alarms, filtered to _SL interfaces
  path-metrics  CloudFlare DNS ICMP probe metrics for branch sites
  all           Run all three (default)

Usage:
    python query.py                                              # all, last 7 days
    python query.py --run di-down --days 3
    python query.py --run incidents --hours 24
    python query.py --run path-metrics --hours 12
    python query.py --run all --days 7
    python query.py --run di-down --start 2026-09-30T00:00:00Z --end 2026-10-07T00:00:00Z
"""

import prisma_sase
import argparse
import sys
import os
import csv
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta

sys.path.append(os.getcwd())

try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID
except ImportError:
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None

PROBE_ID = "1782227402608020408"  # CloudFlare DNS ICMP Response (direct path)
BRANCH_PREFIXES = ("TR", "BUB", "RST_Bub")


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def login() -> prisma_sase.API:
    session = prisma_sase.API()
    session.interactive.login_secret(
        client_id=PRISMASASE_CLIENT_ID,
        client_secret=PRISMASASE_CLIENT_SECRET,
        tsg_id=PRISMASASE_TSG_ID,
    )
    return session


def build_id_maps(cgx) -> tuple[dict, dict]:
    print("  Building site/element lookup tables...")
    sites_resp = cgx.get.sites()
    sites = sites_resp.cgx_content.get("items", []) if sites_resp.cgx_status else []
    site_map = {s["id"]: s["name"] for s in sites}

    elements_resp = cgx.get.elements()
    elements = elements_resp.cgx_content.get("items", []) if elements_resp.cgx_status else []
    element_map = {e["id"]: e.get("name", "") for e in elements}

    print(f"  Loaded {len(site_map)} sites, {len(element_map)} elements")
    return site_map, element_map


def build_events_query(code: str, start_time: str, end_time: str, count: int, dest_page: int = 0) -> dict:
    return {
        "limit": {"count": count, "sort_on": "time", "sort_order": "descending"},
        "dest_page": dest_page,
        "view": {"summary": False},
        "priority": [],
        "severity": [],
        "element_cluster_roles": [],
        "query": {
            "site": [],
            "category": [],
            "code": [code],
            "correlation_id": [],
            "type": ["alarm"],
        },
        "start_time": start_time,
        "end_time": end_time,
    }


def fetch_all_incidents(cgx, code: str, start_time: str, end_time: str, count: int) -> list:
    all_items = []
    dest_page = 0
    while True:
        payload = build_events_query(code, start_time, end_time, count, dest_page)
        print(f"  Fetching page {dest_page} (up to {count} results)...")
        resp = cgx.post.query_events(data=payload)
        if not resp.cgx_status:
            print(f"  [ERROR] API call failed: {resp.cgx_content}")
            break
        content = resp.cgx_content
        items = content.get("items", [])
        all_items.extend(items)
        total_count = content.get("total_count", len(all_items))
        print(f"  Got {len(items)} items (total so far: {len(all_items)} of {total_count})")
        if len(items) < count or len(all_items) >= total_count:
            break
        dest_page += 1
    return all_items


def write_csv(rows: list, path: str, fieldnames: list | None = None):
    if not rows:
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Exported {len(rows)} rows to: {path}")


# ---------------------------------------------------------------------------
# DI Down query
# ---------------------------------------------------------------------------

def _build_circuit_label_map(cgx, items: list) -> dict:
    unique_sites = {item.get("site_id") for item in items if item.get("site_id")}
    wan_name: dict[str, dict[str, str]] = {}
    print(f"  Fetching WAN interfaces for {len(unique_sites)} sites...")
    for site_id in unique_sites:
        resp = cgx.get.waninterfaces(site_id)
        if not resp.cgx_status:
            continue
        wan_name[site_id] = {
            wan_if["id"]: wan_if.get("name", "")
            for wan_if in resp.cgx_content.get("items", [])
            if wan_if.get("id")
        }

    pairs = {
        (item.get("site_id"), item.get("element_id"))
        for item in items if item.get("site_id") and item.get("element_id")
    }
    result: dict[tuple, str] = {}
    print(f"  Fetching interfaces for {len(pairs)} site/element pairs...")
    for (site_id, element_id) in pairs:
        resp = cgx.get.interfaces(site_id, element_id)
        if not resp.cgx_status:
            continue
        site_wan = wan_name.get(site_id, {})
        for iface in resp.cgx_content.get("items", []):
            if_id = iface.get("id", "")
            wan_ids = iface.get("site_wan_interface_ids") or []
            circuit_label = next((site_wan[wid] for wid in wan_ids if wid in site_wan), "")
            if if_id:
                result[(site_id, element_id, if_id)] = circuit_label

    print(f"  Circuit label map built: {len(result)} entries")
    return result


def _flatten_di_down(item: dict, site_map: dict, element_map: dict, circuit_label_map: dict) -> dict:
    info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
    site_id = item.get("site_id", "")
    element_id = item.get("element_id", "")
    if_name = info.get("name", "")
    if_id = info.get("if_id") or info.get("interface_id") or info.get("id") or ""
    circuit_label = (
        circuit_label_map.get((site_id, element_id, if_id))
        or circuit_label_map.get((site_id, element_id, if_name))
        or info.get("circuit_labels", "")
    )
    return {
        "id": item.get("id", ""),
        "time": item.get("time", ""),
        "cleared_time": item.get("cleared_time", ""),
        "code": item.get("code", ""),
        "type": item.get("type", ""),
        "severity": item.get("severity", ""),
        "priority": item.get("priority", ""),
        "site_id": site_id,
        "site_name": site_map.get(site_id, item.get("site_name", "")),
        "element_id": element_id,
        "element_name": element_map.get(element_id, item.get("element_name", "")),
        "circuit_name": if_name,
        "circuit_label": circuit_label,
        "extended_state": info.get("extended_state", ""),
        "description": item.get("description", ""),
        "correlation_id": item.get("correlation_id", ""),
        "info": json.dumps(info) if info else "",
    }


def _analyze_incidents(flat_items: list, output_path: str, key_col: str = "circuit_label",
                       none_label: str = "(none)"):
    counts = defaultdict(lambda: defaultdict(int))
    all_states: set[str] = set()
    for row in flat_items:
        key = (row["site_name"], row.get(key_col, "") or "(unknown)")
        state = row.get("extended_state", "") or none_label
        counts[key][state] += 1
        all_states.add(state)

    all_states_sorted = sorted(all_states)
    sorted_keys = sorted(counts.keys())

    print(f"\n--- Extended State Counts ({len(sorted_keys)} site/{key_col} combinations) ---")
    col_w = 6
    header = f"  {'Site':<35} {key_col:<25} " + "  ".join(f"{s[:col_w]:>{col_w}}" for s in all_states_sorted)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for (site, label) in sorted_keys:
        row_counts = "  ".join(f"{counts[(site, label)].get(s, 0):>{col_w}}" for s in all_states_sorted)
        print(f"  {site:<35} {label:<25} {row_counts}")

    fieldnames = ["site_name", key_col] + all_states_sorted
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for (site, label) in sorted_keys:
            row = {"site_name": site, key_col: label}
            for state in all_states_sorted:
                row[state] = counts[(site, label)].get(state, 0)
            writer.writerow(row)
    print(f"Analysis exported to: {output_path}")


def run_di_down(cgx, args):
    print(f"\n=== DI Down ({args.di_code}) ===")
    print(f"  Window: {args.start}  ->  {args.end}")
    print(f"  Output: {args.di_output}")

    site_map, element_map = build_id_maps(cgx)

    print("\nFetching incidents...")
    items = fetch_all_incidents(cgx, args.di_code, args.start, args.end, args.count)
    if not items:
        print("No incidents found.")
        return

    print("\nBuilding circuit label map...")
    circuit_label_map = _build_circuit_label_map(cgx, items)

    flat_items = [_flatten_di_down(i, site_map, element_map, circuit_label_map) for i in items]
    stem = args.di_output.removesuffix(".csv")
    write_csv(flat_items, args.di_output)
    _analyze_incidents(flat_items, f"{stem}_analysis.csv", key_col="circuit_label",
                       none_label="Direct_Internet_Down")


# ---------------------------------------------------------------------------
# Incidents (_SL) query
# ---------------------------------------------------------------------------

def _filter_sl_interfaces(items: list) -> list:
    kept, skipped = [], 0
    for item in items:
        info = item.get("info", {})
        name = info.get("name", "") if isinstance(info, dict) else ""
        if "_SL" in name:
            kept.append(item)
        else:
            skipped += 1
    print(f"  _SL filter: kept {len(kept)}, skipped {skipped}")
    return kept


def _flatten_incident(item: dict, site_map: dict, element_map: dict) -> dict:
    info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
    site_id = item.get("site_id", "")
    element_id = item.get("element_id", "")
    return {
        "id": item.get("id", ""),
        "time": item.get("time", ""),
        "cleared_time": item.get("cleared_time", ""),
        "code": item.get("code", ""),
        "type": item.get("type", ""),
        "severity": item.get("severity", ""),
        "priority": item.get("priority", ""),
        "site_id": site_id,
        "site_name": site_map.get(site_id, item.get("site_name", "")),
        "element_id": element_id,
        "element_name": element_map.get(element_id, item.get("element_name", "")),
        "interface_name": info.get("name", ""),
        "circuit_label": info.get("circuit_labels", ""),
        "extended_state": info.get("extended_state", ""),
        "description": item.get("description", ""),
        "correlation_id": item.get("correlation_id", ""),
        "info": json.dumps(info) if info else "",
    }


def run_incidents(cgx, args):
    print(f"\n=== Incidents (_SL filter, {args.inc_code}) ===")
    print(f"  Window: {args.start}  ->  {args.end}")
    print(f"  Output: {args.inc_output}")

    site_map, element_map = build_id_maps(cgx)

    print("\nFetching incidents...")
    items = fetch_all_incidents(cgx, args.inc_code, args.start, args.end, args.count)
    if not items:
        print("No incidents found.")
        return

    print("\nFiltering to _SL interfaces...")
    items = _filter_sl_interfaces(items)
    if not items:
        print("No incidents remain after _SL filter.")
        return

    flat_items = [_flatten_incident(i, site_map, element_map) for i in items]

    keep_states = {"liveliness_down", "lowerlayer_down"}
    before = len(flat_items)
    flat_items = [r for r in flat_items if r.get("extended_state") in keep_states]
    print(f"  extended_state filter: kept {len(flat_items)}, skipped {before - len(flat_items)}")

    if not flat_items:
        print("No incidents remain after extended_state filter.")
        return

    stem = args.inc_output.removesuffix(".csv")
    write_csv(flat_items, args.inc_output)
    _analyze_incidents(flat_items, f"{stem}_analysis.csv", key_col="circuit_label")


# ---------------------------------------------------------------------------
# Path metrics query
# ---------------------------------------------------------------------------

def _is_branch_site(name: str) -> bool:
    return name.startswith(BRANCH_PREFIXES)


def _extract_stats(metrics_list: list, metric_idx: int):
    try:
        datapoints = metrics_list[metric_idx]["series"][0]["data"][0]["datapoints"]
        vals = [p["value"] for p in datapoints if p.get("value") is not None]
        if not vals:
            return None, None
        return round(sum(vals) / len(vals), 3), round(max(vals), 3)
    except (IndexError, KeyError, TypeError):
        return None, None


def _query_probe(cgx, site_id: str, wif_id: str, start_time: str, end_time: str):
    payload = {
        "start_time": start_time,
        "end_time": end_time,
        "interval": "5min",
        "metrics": [
            {"name": "ProbeLatency",    "statistics": ["average"], "unit": "milliseconds"},
            {"name": "ProbePacketLoss", "statistics": ["average"], "unit": "Percentage"},
            {"name": "ProbeJitter",     "statistics": ["average"], "unit": "milliseconds"},
        ],
        "view": {},
        "filter": {
            "site": [site_id],
            "path": [wif_id],
            "probe_config": [PROBE_ID],
        },
    }
    resp = cgx.post.monitor_metrics_probes(data=payload)
    if not resp.cgx_status:
        return None, None, None, None, None, None
    metrics = resp.cgx_content.get("metrics", [])
    lat_avg,    lat_max    = _extract_stats(metrics, 0)
    pl_avg,     pl_max     = _extract_stats(metrics, 1)
    jitter_avg, jitter_max = _extract_stats(metrics, 2)
    return lat_avg, lat_max, pl_avg, pl_max, jitter_avg, jitter_max


def run_path_metrics(cgx, args):
    # Path metrics API rejects windows ending at the current moment
    end_time = args.pm_end
    start_time = args.start

    print(f"\n=== Path Metrics (CloudFlare DNS ICMP probe) ===")
    print(f"  Probe: {PROBE_ID}")
    print(f"  Window: {start_time}  ->  {end_time}")
    print(f"  Output: {args.pm_output}")

    sites_resp = cgx.get.sites()
    if not sites_resp.cgx_status:
        print("[ERROR] Could not fetch sites.")
        return

    branch_sites = [
        s for s in sites_resp.cgx_content.get("items", [])
        if _is_branch_site(s.get("name", ""))
    ]
    print(f"Branch sites found: {len(branch_sites)}\n")

    rows = []
    skipped = 0

    for site in sorted(branch_sites, key=lambda s: s["name"]):
        site_id = site["id"]
        site_name = site["name"]

        wanifs_resp = cgx.get.waninterfaces(site_id)
        if not wanifs_resp.cgx_status:
            print(f"  [{site_name}] SKIP — could not fetch WAN interfaces")
            skipped += 1
            continue

        wan_interfaces = wanifs_resp.cgx_content.get("items", [])
        if not wan_interfaces:
            skipped += 1
            continue

        for wif in wan_interfaces:
            wif_id = wif.get("id", "")
            circuit_name = wif.get("name", "")
            if not wif_id:
                continue

            lat_avg, lat_max, pl_avg, pl_max, jitter_avg, jitter_max = _query_probe(
                cgx, site_id, wif_id, start_time, end_time
            )
            if all(v is None for v in (lat_avg, pl_avg, jitter_avg)):
                print(f"  [{site_name}] {circuit_name} — no data")
                continue

            print(
                f"  [{site_name}] {circuit_name} — "
                f"latency={lat_avg}/{lat_max} ms  "
                f"packet_loss={pl_avg}/{pl_max}%  "
                f"jitter={jitter_avg}/{jitter_max} ms"
            )
            rows.append({
                "site_name":             site_name,
                "circuit_name":          circuit_name,
                "avg_latency_ms":        lat_avg    if lat_avg    is not None else "",
                "max_latency_ms":        lat_max    if lat_max    is not None else "",
                "avg_packet_loss_pct":   pl_avg     if pl_avg     is not None else "",
                "max_packet_loss_pct":   pl_max     if pl_max     is not None else "",
                "avg_jitter_ms":         jitter_avg if jitter_avg is not None else "",
                "max_jitter_ms":         jitter_max if jitter_max is not None else "",
            })

    print(f"\nDone. {len(rows)} circuits with data, {skipped} sites skipped.")
    fieldnames = [
        "site_name", "circuit_name",
        "avg_latency_ms", "max_latency_ms",
        "avg_packet_loss_pct", "max_packet_loss_pct",
        "avg_jitter_ms", "max_jitter_ms",
    ]
    write_csv(rows, args.pm_output, fieldnames)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def go():
    now = datetime.now(timezone.utc)
    default_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    default_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # Path metrics API rejects windows that end at the exact current moment
    pm_default_end = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    parser = argparse.ArgumentParser(
        description="Combined Prisma SD-WAN query tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Queries:
  di-down       NETWORK_DIRECTINTERNET_DOWN alarms
  incidents     DEVICEHW_INTERFACE_DOWN alarms filtered to _SL interfaces
  path-metrics  CloudFlare DNS ICMP probe metrics for branch sites
  all           Run all three (default)

Examples:
  python query.py                                # all, last 7 days
  python query.py --run di-down --days 3
  python query.py --run incidents --hours 24
  python query.py --run path-metrics --hours 12
  python query.py --run all --days 7
  python query.py --run di-down --start 2026-09-30T00:00:00Z --end 2026-10-07T00:00:00Z
""",
    )

    # Which query to run
    parser.add_argument(
        "--run",
        choices=["di-down", "incidents", "path-metrics", "all"],
        default="all",
        metavar="{di-down,incidents,path-metrics,all}",
        help="Which query to run (default: all)",
    )

    # Shared time range
    time_group = parser.add_argument_group("time range (shared across all queries)")
    time_group.add_argument("--hours", type=int, default=None,
        help="Lookback window in hours from now (overrides --days/--start/--end)")
    time_group.add_argument("--days", type=int, default=None,
        help="Lookback window in days from now (overrides --start/--end)")
    time_group.add_argument("--start", default=default_start,
        help=f"Start time ISO 8601 UTC (default: 7 days ago)")
    time_group.add_argument("--end", default=default_end,
        help="End time ISO 8601 UTC (default: now)")

    # Alarm query options
    alarm_group = parser.add_argument_group("alarm query options (di-down / incidents)")
    alarm_group.add_argument("--count", type=int, default=25,
        help="Page size for each API alarm request (default: 25)")
    alarm_group.add_argument("--di-code", default="NETWORK_DIRECTINTERNET_DOWN",
        dest="di_code",
        help="Alarm code for di-down query (default: NETWORK_DIRECTINTERNET_DOWN)")
    alarm_group.add_argument("--inc-code", default="DEVICEHW_INTERFACE_DOWN",
        dest="inc_code",
        help="Alarm code for incidents query (default: DEVICEHW_INTERFACE_DOWN)")

    # Output files
    out_group = parser.add_argument_group("output files")
    out_group.add_argument("--di-output", default="di_down_incidents.csv", dest="di_output",
        help="Output CSV for di-down (default: di_down_incidents.csv)")
    out_group.add_argument("--inc-output", default="incidents.csv", dest="inc_output",
        help="Output CSV for incidents (default: incidents.csv)")
    out_group.add_argument("--pm-output", default="path_metrics.csv", dest="pm_output",
        help="Output CSV for path-metrics (default: path_metrics.csv)")

    args = parser.parse_args()

    # Resolve time range
    if args.hours is not None:
        args.end   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        args.start = (now - timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    elif args.days is not None:
        args.end   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        args.start = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Path metrics needs end slightly before now; reuse shared end unless overridden
    args.pm_end = args.end if args.end != default_end else pm_default_end

    print("\nLogging in to Prisma SASE...")
    cgx = login()

    runs = {
        "di-down":      run_di_down,
        "incidents":    run_incidents,
        "path-metrics": run_path_metrics,
    }

    if args.run == "all":
        for name, fn in runs.items():
            fn(cgx, args)
    else:
        runs[args.run](cgx, args)

    print("\nDone.")


if __name__ == "__main__":
    go()
