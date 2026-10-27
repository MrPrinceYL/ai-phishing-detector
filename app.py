"""Streamlit front end: paste a URL, get a risk score and the reasons."""

import streamlit as st

from detector.heuristics import analyze_url, risk_level, risk_score

st.set_page_config(page_title="AI Phishing Detector", page_icon="🎣")
st.title("🎣 AI Phishing Detector")
st.caption("Checks URLs for typical phishing signs. Nothing is stored.")

content = st.text_input("URL", placeholder="https://paypal.secure-login.xyz/verify")

if st.button("Analyse", type="primary") and content.strip():
    findings = analyze_url(content)
    score = risk_score(findings)
    level = risk_level(score)

    show = {"low": st.success, "medium": st.warning, "high": st.error}[level]
    show(f"Risk score {score}/100 ({level})")
    st.progress(score / 100)
    for f in findings:
        st.write(f"- **+{f.weight}** {f.reason}")
    if not findings:
        st.write("No known warning signs found. That is not a guarantee that it is safe.")
