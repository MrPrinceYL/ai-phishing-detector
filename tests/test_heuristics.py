from detector.heuristics import analyze_url


def reasons(findings):
    return " ".join(f.reason for f in findings)


def test_clean_url_has_no_findings():
    assert analyze_url("https://www.paypal.com/de/signin") == []


def test_brand_on_foreign_domain():
    findings = analyze_url("https://paypal.secure-login.xyz/verify")
    assert "Mentions 'paypal'" in reasons(findings)
    assert ".xyz" in reasons(findings)


def test_ip_and_at_sign():
    text = reasons(analyze_url("http://user@192.168.0.10/login"))
    assert "raw IP address" in text
    assert "'@'" in text
