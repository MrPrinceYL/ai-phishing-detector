"""Rule-based phishing checks for URLs and e-mail texts.

Every check adds a Finding with a weight. The weights add up to a risk score
(0-100). The rules are simple on purpose: they are easy to read, easy to test
and explain *why* something looks suspicious.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Finding:
    reason: str
    weight: int


def analyze_url(url: str) -> list[Finding]:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []

    if parsed.scheme != "https":
        findings.append(Finding("No HTTPS: the connection is not encrypted", 10))

    return findings


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(f.weight for f in findings))


