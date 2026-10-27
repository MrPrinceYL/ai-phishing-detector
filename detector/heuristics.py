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


# TLDs that show up a lot in phishing campaigns (cheap or free to register).
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly"}

def analyze_url(url: str) -> list[Finding]:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []

    if parsed.scheme != "https":
        findings.append(Finding("No HTTPS: the connection is not encrypted", 10))

    try:
        ipaddress.ip_address(host)
        findings.append(Finding("The link uses a raw IP address instead of a domain name", 25))
    except ValueError:
        pass

    if "@" in parsed.netloc:
        findings.append(Finding("'@' in the address: everything before it is ignored by the browser", 25))

    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding("Punycode domain: may imitate another domain with look-alike letters", 20))

    if host.count(".") >= 4:
        findings.append(Finding("Unusually many subdomains", 10))

    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        findings.append(Finding(f"Top-level domain '.{host.rsplit('.', 1)[-1]}' is common in phishing", 15))

    if host in SHORTENERS:
        findings.append(Finding("URL shortener hides the real destination", 15))

    if host.count("-") >= 3:
        findings.append(Finding("Many hyphens in the domain name", 10))

    if len(url) > 100:
        findings.append(Finding("Very long URL", 5))

    return findings


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(f.weight for f in findings))


