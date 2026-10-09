# SignalShield — evidence-first scam and prompt-injection triage

**Track:** AI + Cybersecurity  
**Status:** Hackathon/portfolio prototype

SignalShield is packaged as a flat, no-subfolders deployment so it can be uploaded through GitHub’s file uploader. SignalShield helps people inspect suspicious scholarship offers, job messages, payment requests, and messages containing instructions aimed at an AI agent. It extracts explainable warning signals, quotes the relevant text, and provides safer verification steps.

It is designed around a simple principle: **show evidence, explain uncertainty, and help the user verify independently.**

## Why this project?

AI-enabled impersonation and convincing scam messages make it harder for people to decide what to trust. Generic “scam or safe?” classifiers can create false confidence. SignalShield instead produces a triage report: the exact phrases that triggered local checks, why they matter, a transparent indicator score, and a verification checklist.

### What is implemented

- Responsive web interface with sample scenarios.
- Flask API endpoint: `POST /api/analyze`.
- Transparent local pattern checks for urgency, payment demands, sensitive-data requests, shortened URLs, impersonation language, secrecy, reward lures, and AI-directed prompt injection.
- Evidence snippets, signal severity, next-step recommendations, URL/email extraction, and explicit limitations.
- Optional OpenAI-compatible model integration for richer explanations.
- Scholarship and job contexts add relevant verification steps.
- Health endpoint at `GET /api/health`.
- Unit tests for core indicators.

### What is not claimed

This prototype does not guarantee scam detection. It does not authenticate senders, browse or resolve links, inspect attachments, or determine whether a message is safe. Its local score is a heuristic indicator score, **not** a calibrated probability. Optional model output may be wrong and should be reviewed.

## Run locally

Python 3.10+ recommended.

```bash
python -m venv .venv
```

Windows:
```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

macOS/Linux:
```bash
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Optional AI model

By default, the app uses transparent local checks and requires no API key. To enable an OpenAI-compatible chat-completions provider, set environment variables:

Windows PowerShell:
```powershell
$env:OPENAI_API_KEY="your-key"
$env:OPENAI_BASE_URL="https://api.featherless.ai/v1"
$env:AI_MODEL="Qwen/Qwen2.5-7B-Instruct"
python app.py
```

macOS/Linux:
```bash
export OPENAI_API_KEY="your-key"
export OPENAI_BASE_URL="https://api.featherless.ai/v1"
export AI_MODEL="Qwen/Qwen2.5-7B-Instruct"
python app.py
```

Use only an API key you are authorized to use. Never commit `.env` files or keys. Provider model names and base URLs can change; check your provider's current documentation.

## API example

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"context":"scholarship","message":"Pay a processing fee within 24 hours to secure your guaranteed scholarship."}'
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Architecture

```text
Browser UI
   │ POST /api/analyze
   ▼
Flask API ───────► Transparent local indicator engine
   │                           │
   │ optional configured       ├─ matched evidence snippets
   │ model provider            ├─ heuristic score + risk band
   ▼                           └─ verification checklist
OpenAI-compatible API
   │
   ▼
Extra explanation signals (untrusted; treated as advisory)
```

## Demo flow (about 2 minutes)

1. Introduce the problem: convincing messages can pressure people into sending money or sensitive data.
2. Select **Fake scholarship** and click **Analyze message**.
3. Show the pressure, payment, sensitive-data, suspicious-link, and secrecy indicators with quoted evidence.
4. Explain that the app does not call something “safe” just because the score is low.
5. Select **AI prompt injection** and show the explicit warning about treating email content as untrusted data.
6. End with the verification checklist and limitations.

## Suggested next steps

- Add safe URL reputation lookups through a reputable API, with clear privacy disclosures.
- Add sender-domain similarity checks using public suffix parsing and carefully sourced official domains.
- Add a benchmark dataset of benign and malicious examples, with precision/recall and false-positive analysis.
- Add a policy-gated email-agent integration that quarantines messages before any tool action.
- Add localization and accessible explanations.

## Privacy

The app does not save analyzed messages to a database. In optional AI mode, the submitted message is sent to the configured provider; do not send private messages or sensitive personal data unless you have permission and have reviewed that provider's data practices.

## License

MIT. See `LICENSE`.


## Deploy a public demo (Render)

This repository includes `render.yaml` for Render Blueprint deployment.

1. Push this project to a GitHub repository.
2. Sign in to Render and choose **New → Blueprint**.
3. Connect the GitHub repository containing `render.yaml`.
4. Review the service settings and deploy.
5. Wait for the deploy to finish, then open the `onrender.com` URL Render provides.
6. Test the public link in a private/incognito browser window and try the sample messages.

The default deployment works without an AI API key using local indicator checks. To enable optional model analysis, add `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `AI_MODEL` as environment variables in the Render service settings. Never put API keys in source code or commit them to GitHub.

Free hosting may spin down when idle and can take a short time to wake up. Check the host's current free-plan terms before submitting.


## Flat GitHub upload layout

All runtime files are intentionally at the repository root: `app.py`, `analyzer.py`, `index.html`, `style.css`, `app.js`, `requirements.txt`, `Procfile`, and `render.yaml`. The Flask app serves these root-level assets directly; no `templates/` or `static/` folders are required. The test file is `test_analyzer.py`.
