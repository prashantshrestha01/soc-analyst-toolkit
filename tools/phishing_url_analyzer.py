#!/usr/bin/env python3
"""Heuristic phishing-URL analyzer.

Scores a URL 0-100 based on common phishing traits and prints the score,
a verdict, and the reasons. Heuristics are not proof of malice — they
prioritize URLs for analyst review.

Usage:
    python3 phishing_url_analyzer.py "http://example.com/login"
"""
import json
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".ru", ".cn",
                   ".tk", ".ml", ".ga", ".cf", ".gq", ".biz", ".work", ".cam",
                   ".country", ".stream", ".download", ".review"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "shorturl.at", "cutt.ly", "rebrand.ly"}
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com",
          "apple": "apple.com", "amazon": "amazon.com", "google": "google.com",
          "netflix": "netflix.com", "chase": "chase.com",
          "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
          "dhl": "dhl.com", "fedex": "fedex.com", "instagram": "instagram.com",
          "facebook": "facebook.com", "linkedin": "linkedin.com"}
CRED_KEYWORDS = ("login", "verify", "secure", "account", "update", "confirm",
                 "password", "signin", "support", "billing")
LEET = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "@": "a",
                      "$": "s", "!": "i", "7": "t"})


def is_brand_domain(host: str) -> bool:
    return any(host == legit or host.endswith("." + legit)
               for legit in set(BRANDS.values()))


def analyze(url: str) -> dict:
    url = url.strip()
    reasons = []
    score = 0

    def add(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(f"+{points}: {reason}")

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        return {"url": url, "score": 50, "verdict": "medium",
                "reasons": ["+50: unparseable URL"]}

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    if not host:
        return {"url": url, "score": 50, "verdict": "medium",
                "reasons": ["+50: no host found"]}

    if "xn--" in host:
        add(25, "punycode (IDN homograph attack risk)")
    if "@" in url.split("://", 1)[-1]:
        add(20, "'@' in URL (credential/redirect trick)")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        add(25, "IP literal as host (no domain name)")
    labels = host.split(".")
    if len(labels) > 4:
        add(10, f"excessive subdomains ({len(labels) - 2} levels)")
    if host in SHORTENERS or host.endswith(tuple("." + s for s in SHORTENERS)):
        add(15, "URL shortener (hides destination)")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        add(10, "suspicious top-level domain")
    # brand impersonation, checked against leet-speak-normalized host
    # (attackers write paypa1, micr0soft, etc.)
    normalized = host.translate(LEET)
    for brand, legit in BRANDS.items():
        if brand in normalized.replace(".", "") and not is_brand_domain(host):
            add(20, f"possible {brand} impersonation (host is not {legit})")
            break
    if host.count("-") >= 3:
        add(10, "excessive hyphens in domain")
    if not is_brand_domain(host) and any(k in host for k in CRED_KEYWORDS):
        add(10, "credential-harvesting keywords in domain on non-brand domain")
    if len(url) > 150:
        add(10, "very long URL (>150 chars)")
    elif len(url) > 75:
        add(5, "long URL (>75 chars)")
    if parsed.scheme == "http":
        add(5, "plain HTTP (no TLS)")
    if re.search(r"(login|verify|secure|account|update|confirm|password|signin)",
                 path, re.IGNORECASE) and not is_brand_domain(host):
        add(10, "credential-harvesting keywords in path on non-brand domain")

    score = min(score, 100)
    verdict = ("low" if score < 25 else "medium" if score < 50
               else "high" if score < 75 else "critical")
    return {"url": url, "host": host, "score": score,
            "verdict": verdict, "reasons": reasons}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    print(json.dumps(analyze(sys.argv[1]), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
