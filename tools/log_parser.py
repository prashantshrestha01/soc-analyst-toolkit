#!/usr/bin/env python3
"""Parse auth-style logs and flag suspicious access patterns.

Supports OpenSSH syslog lines and ISO-timestamp 'user ip result' lines, e.g.:
    2026-10-19T09:14:22Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234
    2026-10-19T09:15:01Z sshd[1235]: Accepted password for analyst from 198.51.100.7 port 52311

Detects:
  - brute-force bursts: >= threshold failures from one IP within <window> minutes
  - off-hours successful logins (default 22:00-06:00 UTC)
  - successful login from an IP never seen before for that user

Usage:
    python3 log_parser.py auth.log [--threshold 5] [--window 10]
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

SSHD = re.compile(
    r"^(?P<ts>\S+)\s+\S*sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+\S+"
    r"(?:\s+for\s+(?:invalid user\s+)?(?P<user>\S+))?\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)
SIMPLE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<user>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<result>FAIL|SUCCESS|Failed|Accepted)\b",
    re.IGNORECASE,
)


def parse_ts(raw: str):
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(year=dt.year if dt.year != 1900 else 2026)
        except ValueError:
            continue
    return None


def parse_line(line: str):
    m = SSHD.match(line) or SIMPLE.match(line)
    if not m:
        return None
    ts = parse_ts(m.group("ts"))
    if ts is None:
        return None
    result = m.group("result").lower()
    success = result in ("accepted", "success")
    return {"ts": ts, "user": m.group("user") or "unknown",
            "ip": m.group("ip"), "success": success}


def analyze(events, threshold=5, window_min=10, off_start=22, off_end=6):
    findings = []
    fails_by_ip = defaultdict(list)
    seen_ip_user = set()
    for e in events:
        if not e["success"]:
            fails_by_ip[e["ip"]].append(e["ts"])
        key = (e["user"], e["ip"])
        if e["success"] and key not in seen_ip_user:
            seen_ip_user.add(key)
            findings.append({
                "type": "new_source_success",
                "severity": "medium",
                "detail": f"first successful login for user '{e['user']}' from {e['ip']}",
                "ts": e["ts"].isoformat(),
            })
        if e["success"] and (e["ts"].hour >= off_start or e["ts"].hour < off_end):
            findings.append({
                "type": "off_hours_login",
                "severity": "low",
                "detail": f"successful login for '{e['user']}' from {e['ip']} at {e['ts'].strftime('%H:%M')} UTC",
                "ts": e["ts"].isoformat(),
            })
    window = timedelta(minutes=window_min)
    for ip, times in fails_by_ip.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 >= threshold:
                findings.append({
                    "type": "brute_force_burst",
                    "severity": "high",
                    "detail": f"{end - start + 1} failed logins from {ip} within {window_min} minutes",
                    "ts": times[end].isoformat(),
                })
                break  # one finding per IP keeps output readable
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: order[f["severity"]])
    return {
        "events_parsed": len(events),
        "failed": sum(1 for e in events if not e["success"]),
        "successful": sum(1 for e in events if e["success"]),
        "findings": findings,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--threshold", type=int, default=5)
    ap.add_argument("--window", type=int, default=10)
    args = ap.parse_args()
    events = []
    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line.strip())
            if e:
                events.append(e)
    print(json.dumps(analyze(events, args.threshold, args.window), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
