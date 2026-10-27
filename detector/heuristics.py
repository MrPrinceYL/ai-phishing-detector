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


# Brands that are often impersonated in phishing mails.
BRANDS = ["paypal", "apple", "microsoft", "amazon", "google", "netflix", "dhl",
          "sparkasse", "volksbank", "postbank", "ing", "commerzbank", "ebay"]

# TLDs that show up a lot in phishing campaigns (cheap or free to register).
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly"}

URGENCY_WORDS = ["urgent", "immediately", "within 24 hours", "account suspended", "verify now",
                 "dringend", "sofort", "innerhalb von 24 stunden", "gesperrt", "letzte mahnung"]

CREDENTIAL_WORDS = ["password", "passwort", "pin", "tan", "login", "anmeldedaten",
                    "credit card", "kreditkarte", "iban", "security code"]

def registered_domain(host: str) -> str:
    """Return the last two labels of a host name (example.co.uk -> co.uk)."""
    # ponytail: naive, ignores multi-part suffixes like .co.uk; use the Public Suffix List if that matters
    return ".".join(host.split(".")[-2:])


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

    # A brand name somewhere in the URL, but the real domain belongs to someone else.
    domain = registered_domain(host)
    for brand in BRANDS:
        if re.search(rf"\b{brand}\b", host + parsed.path.lower()) and brand not in domain:
            findings.append(Finding(f"Mentions '{brand}' but the domain is '{domain}'", 30))
            break

    return findings


def analyze_email(text: str) -> list[Finding]:
    lower = text.lower()
    findings = []

    urgent = [w for w in URGENCY_WORDS if w in lower]
    if urgent:
        findings.append(Finding(f"Creates time pressure ({', '.join(urgent)})", 15))

    creds = [w for w in CREDENTIAL_WORDS if re.search(rf"\b{re.escape(w)}\b", lower)]
    if creds:
        findings.append(Finding(f"Asks for sensitive data ({', '.join(creds)})", 25))

    return findings


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(f.weight for f in findings))


