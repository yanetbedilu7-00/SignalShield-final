# SignalShield — submission draft

## Short description
SignalShield turns suspicious messages into evidence-first security reports. It flags scam tactics and AI-directed prompt injection, quotes the evidence, explains uncertainty, and gives users an independent verification checklist.

## Track
AI + Cybersecurity

## Problem
Scams and impersonation often use urgency, payment requests, sensitive-data requests, and realistic-looking messages. AI agents also face a related risk: untrusted email content may try to manipulate the agent into ignoring its instructions or taking unsafe actions.

## Solution
SignalShield combines transparent local indicators with optional AI-assisted analysis. Each report shows the exact evidence, severity, a heuristic score, and practical verification steps. The app deliberately avoids presenting a low score as proof that a message is safe.

## Technical approach
- Flask API and responsive browser interface.
- Rule-based signal extraction for explainability and offline use.
- Optional OpenAI-compatible model for additional analysis.
- Input limits, output escaping, no database persistence, and explicit privacy/limitations notices.
- Tests for payment pressure, prompt injection, and cautious language.

## Impact
The prototype aims to help students, job seekers, and everyday users pause before paying fees, sharing credentials, or trusting an impersonated organization. A future version could add carefully sourced domain reputation checks, measured benchmark performance, and policy-gated email-agent integration.

## Important limitations
The current version does not authenticate senders, resolve URLs, inspect attachments, or guarantee detection. The local score is heuristic, not a calibrated probability. AI output is advisory and can be wrong.
