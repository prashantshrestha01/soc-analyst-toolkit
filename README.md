# SOC Analyst Toolkit

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![SOC](https://img.shields.io/badge/SOC-1F6FEB?style=flat-square) ![Automation](https://img.shields.io/badge/Automation-6E40C9?style=flat-square)


Small, dependency-free Python tools for the repetitive parts of Tier-1 SOC work: pulling IOCs out of reports, triaging suspicious URLs, spotting brute force in auth logs, and ranking an alert queue. Built as lab tooling for my own analyst workflow practice.

## Tools

| Tool | What it does |
|------|--------------|
| `tools/ioc_extractor.py` | Extracts IPv4s, URLs, domains, emails, MD5/SHA1/SHA256 from raw text (handles `hxxp` / `[.]` defanging); outputs JSON |
| `tools/phishing_url_analyzer.py` | Heuristic phishing score 0–100 (punycode, `@` tricks, IP hosts, shorteners, brand impersonation, suspicious TLDs) with reasons |
| `tools/log_parser.py` | Parses OpenSSH-style auth logs; flags brute-force bursts, off-hours successful logins, and first-seen source IPs |
| `tools/alert_prioritizer.py` | Scores a CSV alert queue by severity × source reliability × asset criticality; outputs ranked queue |

## Install

Standard library only — no `pip install` needed. Python 3.8+.

## Usage

```bash
# Pull IOCs from a phishing report (file or stdin)
python3 tools/ioc_extractor.py samples/sample_iocs.txt

# Score a suspicious URL
python3 tools/phishing_url_analyzer.py "http://paypa1-secure.login-verify.top/signin"

# Hunt brute force in an auth log
python3 tools/log_parser.py /var/log/auth.log --threshold 5 --window 10

# Rank an alert queue (JSON by default, --format csv for CSV)
python3 tools/alert_prioritizer.py samples/sample_alerts.csv
```

## Samples & tests

- `samples/sample_iocs.txt` — synthetic phishing email with defanged IOCs
- `samples/sample_alerts.csv` — 12-alert queue fixture
- `tests/test_smoke.py` — runs every tool against the fixtures and asserts well-formed output

```bash
python3 tests/test_smoke.py
```

## Notes

Heuristics prioritize work for an analyst; they don't prove malice. Thresholds (brute-force burst size, off-hours window, scoring weights) are tunable via CLI flags or constants at the top of each script.

---

### 👤 About the author

**Prashant Shrestha** — Cybersecurity Specialist (CDI College, in progress) · 11+ years across SOC analysis, penetration testing & network security · Mississauga, ON 🇨🇦

🔗 [LinkedIn](https://www.linkedin.com/in/cto-prashant/) · 💻 [GitHub](https://github.com/prashantshrestha01)

*Building in public — every project here is my own lab work.*
