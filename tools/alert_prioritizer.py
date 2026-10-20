#!/usr/bin/env python3
"""Prioritize a SOC alert queue.

Reads a CSV of alerts with columns:
    alert_id,title,severity,source,asset,asset_criticality

Scores each alert from severity x source reliability x asset criticality,
then prints the ranked queue as JSON (or CSV with --format csv).

Usage:
    python3 alert_prioritizer.py alerts.csv
    python3 alert_prioritizer.py alerts.csv --format csv
"""
import argparse
import csv
import json
import sys

SEVERITY_W = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0,
              "informational": 0.5, "info": 0.5}
SOURCE_W = {"edr": 1.2, "siem": 1.15, "email_gateway": 1.1, "firewall": 1.0,
            "ids": 1.0, "waf": 1.0, "user_report": 0.9, "ti_feed": 0.8,
            "vuln_scanner": 0.7}
ASSET_W = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 0.75}


def score_alert(row: dict) -> dict:
    sev = SEVERITY_W.get(row["severity"].strip().lower(), 1.0)
    src = SOURCE_W.get(row["source"].strip().lower(), 1.0)
    asset = ASSET_W.get(row["asset_criticality"].strip().lower(), 1.0)
    score = round(min(sev * src * asset / 7.2 * 100, 100), 1)  # max raw 7.2 -> 100
    return {**row, "priority_score": score}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csvfile")
    ap.add_argument("--format", choices=["json", "csv"], default="json")
    args = ap.parse_args()
    with open(args.csvfile, newline="", encoding="utf-8") as f:
        alerts = [score_alert(r) for r in csv.DictReader(f)]
    alerts.sort(key=lambda a: a["priority_score"], reverse=True)
    if args.format == "csv":
        w = csv.DictWriter(sys.stdout, fieldnames=list(alerts[0].keys()))
        w.writeheader()
        w.writerows(alerts)
    else:
        print(json.dumps({"total": len(alerts), "queue": alerts}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
