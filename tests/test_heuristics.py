from detector.heuristics import analyze_email, analyze_url, risk_level, risk_score


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


def test_phishing_mail_scores_high():
    mail = """Dear customer,
    your account suspended! Verify now within 24 hours and enter your password here:
    http://amazon-account.verify-user.top/login"""
    score = risk_score(analyze_email(mail))
    assert risk_level(score) == "high"


def test_normal_mail_scores_low():
    mail = "Hi Tom, the meeting is moved to Friday 10am. See you there!"
    assert risk_level(risk_score(analyze_email(mail))) == "low"
