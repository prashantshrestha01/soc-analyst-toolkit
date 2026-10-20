#!/usr/bin/env python3
"""Smoke tests: run every tool against the sample fixtures and check
the outputs are well-formed. No external dependencies.

Usage: python3 tests/test_smoke.py
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
SAMPLES = ROOT / "samples"


def run(*args):
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True)
    assert p.returncode == 0, f"{args} exited {p.returncode}: {p.stderr}"
    return p.stdout


def test_ioc_extractor():
    out = json.loads(run(TOOLS / "ioc_extractor.py", SAMPLES / "sample_iocs.txt"))
    assert "185.220.101.4" in out["ipv4"], "missed plain IP"
    assert "45.155.204.9" in out["ipv4"], "missed defanged IP"
    assert any("paypa1-secure" in u for u in out["urls"]), "missed defanged URL"
    assert "abuse@contoso.com" in out["emails"], "missed email"
    assert out["hashes"]["md5"] == ["5d41402abc4b2a76b9719d911017c592"]
    assert len(out["hashes"]["sha256"]) == 1
    assert out["counts"]["ipv4"] >= 2


def test_phishing_url_analyzer():
    bad = json.loads(run(TOOLS / "phishing_url_analyzer.py",
                         "http://paypa1-secure.login-verify.top/signin"))
    assert bad["score"] >= 50, f"phishy URL scored too low: {bad['score']}"
    assert bad["verdict"] in ("high", "critical")
    assert bad["reasons"], "no reasons given"
    good = json.loads(run(TOOLS / "phishing_url_analyzer.py",
                          "https://www.microsoft.com/en-us/security"))
    assert good["score"] < 25, f"legit URL scored too high: {good['score']}"


def test_log_parser():
    log = SAMPLES / "sample_auth.log"
    log.write_text(
        "2026-10-19T09:14:22Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234\n"
        "2026-10-19T09:14:40Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51235\n"
        "2026-10-19T09:15:02Z sshd[1234]: Failed password for invalid user root from 203.0.113.5 port 51236\n"
        "2026-10-19T09:15:20Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51237\n"
        "2026-10-19T09:15:44Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51238\n"
        "2026-10-19T09:16:05Z sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51239\n"
        "2026-10-19T02:30:00Z sshd[1400]: Accepted password for analyst from 198.51.100.7 port 52311\n"
    )
    try:
        out = json.loads(run(TOOLS / "log_parser.py", str(log)))
    finally:
        log.unlink()
    assert out["events_parsed"] == 7
    types = {f["type"] for f in out["findings"]}
    assert "brute_force_burst" in types, "missed brute-force burst"
    assert "off_hours_login" in types, "missed off-hours login"
    assert "new_source_success" in types, "missed new-source success"


def test_alert_prioritizer():
    out = json.loads(run(TOOLS / "alert_prioritizer.py", SAMPLES / "sample_alerts.csv"))
    assert out["total"] == 12
    scores = [a["priority_score"] for a in out["queue"]]
    assert scores == sorted(scores, reverse=True), "queue not ranked"
    top = out["queue"][0]
    assert top["severity"].lower() == "critical", "top alert should be critical"
    assert top["priority_score"] > out["queue"][-1]["priority_score"]


if __name__ == "__main__":
    test_ioc_extractor()
    print("ioc_extractor OK")
    test_phishing_url_analyzer()
    print("phishing_url_analyzer OK")
    test_log_parser()
    print("log_parser OK")
    test_alert_prioritizer()
    print("alert_prioritizer OK")
    print("All smoke tests passed.")
