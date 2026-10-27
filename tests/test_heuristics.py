from detector.heuristics import analyze_url


def reasons(findings):
    return " ".join(f.reason for f in findings)


def test_https_url_has_no_findings():
    assert analyze_url("https://example.com/login") == []


def test_http_is_flagged():
    assert "No HTTPS" in reasons(analyze_url("http://example.com"))
