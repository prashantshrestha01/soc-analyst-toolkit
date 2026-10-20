#!/usr/bin/env python3
"""Extract indicators of compromise (IOCs) from raw text.

Finds IPv4 addresses, URLs, domain names, email addresses, and file hashes
(MD5/SHA1/SHA256). Handles common defanging (hxxp, [.] , (.) ) and prints JSON.

Usage:
    python3 ioc_extractor.py report.txt
    cat report.txt | python3 ioc_extractor.py
"""
import json
import re
import sys

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
URL = re.compile(r"\bhttps?://[^\s'\"<>,\]]+", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,}|xn--[A-Za-z0-9]+)\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def dedefang(text: str) -> str:
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"\bhxxps\b", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp\b", "http", text, flags=re.IGNORECASE)
    return text


def extract(text: str) -> dict:
    text = dedefang(text)
    urls = sorted(set(URL.findall(text)))
    emails = sorted(set(EMAIL.findall(text)))
    # domains: drop ones already covered by urls/emails to reduce noise
    covered = " ".join(urls + emails).lower()
    domains = sorted({d for d in DOMAIN.findall(text) if d.lower() not in covered})
    ips = sorted(set(IPV4.findall(text)), key=lambda ip: tuple(int(p) for p in ip.split(".")))
    hashes = {
        "md5": sorted(set(MD5.findall(text))),
        "sha1": sorted(set(SHA1.findall(text))),
        "sha256": sorted(set(SHA256.findall(text))),
    }
    return {
        "ipv4": ips,
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "hashes": hashes,
        "counts": {
            "ipv4": len(ips),
            "urls": len(urls),
            "domains": len(domains),
            "emails": len(emails),
            "hashes": sum(len(v) for v in hashes.values()),
        },
    }


def main() -> int:
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    print(json.dumps(extract(text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
