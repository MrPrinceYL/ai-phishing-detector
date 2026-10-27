"""Streamlit front end: paste a URL or an e-mail, get a risk score and the reasons."""

import streamlit as st

from detector import ai
from detector.heuristics import analyze_email, analyze_url, risk_level, risk_score

st.set_page_config(page_title="AI Phishing Detector", page_icon="🎣")
st.title("🎣 AI Phishing Detector")
st.caption("Checks URLs and e-mails for typical phishing signs. Nothing is stored.")

mode = st.radio("What do you want to check?", ["URL", "E-mail text"], horizontal=True)
if mode == "URL":
    content = st.text_input("URL", placeholder="https://paypal.secure-login.xyz/verify")
else:
    content = st.text_area("E-mail text", height=220, placeholder="Paste the whole mail here ...")

use_ai = st.checkbox("Ask Claude for a second opinion", value=ai.is_configured(),
                     disabled=not ai.is_configured(),
                     help="Needs ANTHROPIC_API_KEY. The text is sent to the Anthropic API.")

if st.button("Analyse", type="primary") and content.strip():
    findings = analyze_url(content) if mode == "URL" else analyze_email(content)
    score = risk_score(findings)
    level = risk_level(score)

    st.subheader("Rule-based check")
    show = {"low": st.success, "medium": st.warning, "high": st.error}[level]
    show(f"Risk score {score}/100 ({level})")
    st.progress(score / 100)
    for f in findings:
        st.write(f"- **+{f.weight}** {f.reason}")
    if not findings:
        st.write("No known warning signs found. That is not a guarantee that it is safe.")

    if use_ai:
        st.subheader("Claude's assessment")
        with st.spinner("Asking Claude ..."):
            verdict = ai.ai_check(content)
        st.write(f"**Verdict:** {verdict.verdict} ({verdict.confidence}% confident)")
        for reason in verdict.reasons:
            st.write(f"- {reason}")
        st.info(verdict.advice)
