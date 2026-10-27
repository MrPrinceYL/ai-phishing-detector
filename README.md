# 🎣 AI Phishing Detector

A small web tool that checks **URLs** and **e-mail texts** for typical phishing signs and
explains *why* something looks suspicious. It combines two approaches:

1. **Rule-based check** (always on, works offline): a set of readable heuristics produces a risk
   score from 0 to 100 and a list of reasons.
2. **AI second opinion** (optional): Claude reads the whole message like a human would and returns
   a structured verdict (`phishing` / `suspicious` / `legitimate`), its reasons and a tip what to do.

![Python](https://img.shields.io/badge/python-3.11+-blue) ![Streamlit](https://img.shields.io/badge/UI-Streamlit-red)

## Features

| Check | Example | Weight |
|---|---|---|
| Brand name on a foreign domain | `paypal.secure-login.xyz` | 30 |
| Raw IP address as host | `http://192.168.0.10/login` | 25 |
| `@` in the address | `http://paypal.com@evil.com` | 25 |
| Asks for sensitive data | password, TAN, IBAN … | 25 |
| Punycode / look-alike domain | `xn--pypal-4ve.com` | 20 |
| Time pressure | "account suspended", "sofort" … | 15 |
| Suspicious TLD / URL shortener | `.zip`, `.top`, `bit.ly` | 15 |
| No HTTPS, many subdomains / hyphens, generic greeting, very long URL | | 5–10 |

Links inside an e-mail are checked with the URL rules as well. Score ≥ 30 = medium, ≥ 60 = high.
Keywords are in English and German.

## Setup

```bash
git clone https://github.com/MrPrinceYL/ai-phishing-detector.git
cd ai-phishing-detector
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# optional, for the AI second opinion
export ANTHROPIC_API_KEY=sk-ant-...

streamlit run app.py
```

Without an API key the app still works; the AI checkbox is then disabled.

## Tests

```bash
python -m pytest
```

## Project structure

```
app.py                  Streamlit UI
detector/heuristics.py  the rules, risk score and level
detector/ai.py          Claude call with a JSON schema (Pydantic model AiVerdict)
tests/                  pytest tests for the rules
```

## How the AI part works

`detector/ai.py` sends the URL or text to the Anthropic Messages API (`claude-opus-5-5`) with
**structured outputs**: the response has to match the JSON schema generated from the Pydantic model
`AiVerdict`, so the app can show it without fragile text parsing. If the request is declined by a
safety classifier, the API's server-side fallback retries it on another model; if that also
declines, the UI shows an error instead of a result.

## Limitations

- Heuristics produce false positives and miss well-made phishing. Treat the score as a hint.
- The "registered domain" is simply the last two labels (`a.b.co.uk` → `co.uk`); a proper
  implementation would use the Public Suffix List.
- E-mail headers (SPF/DKIM, real sender) are not checked; only the visible text.
- With the AI option on, the content is sent to the Anthropic API. Don't paste confidential mails.

## Ideas for later

- Parse `.eml` files including headers
- Check links against Google Safe Browsing / PhishTank
- Browser extension
