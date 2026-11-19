<div align="center">

<img src="static/logo.png" alt="Aegis Scanner" width="96" height="96">

# Aegis Scanner

**A Flask dashboard for authorised TCP port discovery and rule-based exposure assessment.**

[![CI](https://github.com/deepakcybersecurity/Network-Security-Analyser/actions/workflows/ci.yml/badge.svg)](https://github.com/deepakcybersecurity/Network-Security-Analyser/actions/workflows/ci.yml)
[![CodeQL](https://github.com/deepakcybersecurity/Network-Security-Analyser/actions/workflows/codeql.yml/badge.svg)](https://github.com/deepakcybersecurity/Network-Security-Analyser/actions/workflows/codeql.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-3.1-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.3-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

> [!WARNING]
> **Authorised use only.** Port scanning may be illegal, disruptive, or trigger security
> monitoring when performed without permission. Only scan systems you own or have explicit
> written authorisation to test. See [Ethical use](#ethical-use).

## Overview

Aegis wraps an Nmap TCP connect scan in a hardened Flask API and a single-page dashboard.
It validates the target before Nmap is ever invoked, rates every open port against a
transparent rule set, persists completed scans to SQLite, and exposes history, per-scan
detail, aggregate statistics, and downloadable text reports.

The project is built as a study in **defensive web application engineering** — the scanning
itself is deliberately simple, while input validation, injection resistance, error
sanitisation, rate limiting, and HTTP hardening are treated as the primary deliverable.
Each control is documented in [Security architecture](#security-architecture).

## Features

- **Target validation before execution** — regex allowlist, length bounds, option-argument
  rejection, and DNS resolution, all applied before Nmap is called.
- **Fast TCP connect scan** (`-sT -F`) over the top 100 ports. The AI assistant can
  recommend broader coverage or Nmap service/version detection when useful.
- **AI scan assistant** — describe the authorized audit goal; OpenAI recommends one of four
  reviewed TCP scan profiles. The separate target field is not sent, and the recommendation
  must be selected by the operator before scanning. Avoid putting targets or secrets in the
  goal text because that text is sent to OpenAI.
- **Deterministic Security Score (0 to 100)** — transparent, rule-based exposure heuristic calculated from base 100 points with deterministic deductions per unique exposed TCP listener: `HIGH (-25)`, `MEDIUM (-10)`, `LOW (-3)`. Bounded between 0 and 100, deduplicated by `protocol:port`, and categorized into 5 standardized score bands:
  - `GOOD (90–100)`: Minimal exposure or low-risk listeners.
  - `FAIR (75–89)`: Moderate exposure or single hardened service.
  - `NEEDS IMPROVEMENT (50–74)`: Noticeable exposure or unencrypted web/administration.
  - `POOR (25–49)`: Substantial exposure across multiple high-risk listeners.
  - `CRITICAL (0–24)`: Extreme surface exposure requiring immediate isolation.
- **Network Service Fingerprint Cards** — expandable educational protocol knowledge cards for detected services (covering ports 21, 22, 23, 80, 443, 135, 445, 3306, 3389, and unclassified fallbacks). Details protocol overview, typical usage, security concerns, historical threat context (with explicit non-exploitability caveats), public exposure guidance, defensive hardening steps, authoritative documentation references (RFCs, IANA, NIST), and interactive jump links to remediation playbooks.
- **Transparent risk rules & Deterministic Remediation Playbooks** — every open port is rated `HIGH`, `MEDIUM`, or `LOW` with a written justification. Actionable hardening playbooks, mitigation steps, illustrative commands (Linux, Windows, Firewall), and verification steps are attached to each finding.
- **Multi-Format Report Export** — download technical and executive reports in multiple formats:
  - **Executive PDF** (`?format=pdf`): Server-side ReportLab document with Aegis branding, colored risk badges, repeating table headers, deterministic remediation playbooks, and cached AI analysis.
  - **Structured CSV** (`?format=csv`): Tabular export with built-in CSV formula injection protection (`'`, `=`, `+`, `-`, `@`, `\t`, `\r`).
  - **Structured JSON** (`?format=json`): Schema-validated (`schema_version: "1.0"`) findings payload.
  - **Technical Text** (`?format=txt`): Original plain-text format for shell pipelines and backward compatibility.
- **Scan Comparison & Exposure Diff** — compare two historical scans of the same target to identify newly detected open ports, ports not detected in the later scan, and service version shifts.
- **Visual Risk Dashboard** — self-hosted inline SVG visualizations depicting risk severity distribution, top targets, and activity timeline.
- **AI Security Analyst** — post-scan threat evaluation with prioritized remediation and offline heuristic fallback.
- **Interactive AI Copilot with Dynamic Command Execution** — conversational assistant accessible from the sidebar for natural-language network diagnostic planning and safe in-browser execution:
  - **Natural-Language Command Proposal**: Proposes validated diagnostic plans from a strict registry (Quick scan, Common TCP, All TCP, Service Version Detection `-sT -sV -F`, Full TCP Detailed `-sT -A -T4 -p-`, Bounded Web Service Check, Reverse DNS / Host Diagnostic).
  - **Command Card Metadata**: Explains tool name, command string, purpose, arguments breakdown, performance considerations, operational impact, required permissions, and safety warnings.
  - **In-Browser Execution (`shell=False`)**: Safe execution inside Aegis with explicit confirmation modal, fixed argument arrays, target verification, cancellation controls, and 500 KB output capping.
  - **Automated Post-Execution Analysis**: Discovered open ports and web response observations are automatically parsed and analyzed by the AI Security Analyst with simple-English explanations and confidence ratings.
  - **Main Report Integration**: Findings from executed commands are seamlessly integrated into downloadable PDF, CSV, JSON, and TXT reports without modifying base deterministic ratings.
- **Persistent history** — SQLite-backed scan records, per-port findings, and statistics computed from the database rather than held in memory.
- **Self-contained front end** — no external CDN, no inline scripts, no external fonts; strict Content Security Policy (`default-src 'self'`).

## Interface

The dashboard is a single Jinja template driven by `fetch` calls against the JSON API.
These are the design references it was built from ([`design/`](design/)):

| Dashboard | New scan |
| --- | --- |
| <img src="design/dashboard/screen.png" alt="Dashboard" width="420"> | <img src="design/new_scan/screen.png" alt="New scan" width="420"> |

| Scan results | Scan history |
| --- | --- |
| <img src="design/scan_results/screen.png" alt="Scan results" width="420"> | <img src="design/scan_history/screen.png" alt="Scan history" width="420"> |

## Architecture

```text
                  ┌──────────────────────────────────────────────┐
  Browser         │  Flask (app.py)                              │
 ┌────────┐       │  ┌────────────────────────────────────────┐  │
 │ index  │──────▶│  │ @after_request → security headers      │  │
 │ .html  │ fetch │  │ Flask-Limiter  → 10 scans/min per IP   │  │
 │ script │◀──────│  └────────────────────────────────────────┘  │
 └────────┘  JSON │        │              │                │     │
                  │        ▼              ▼                ▼     │
                  │  scanner.py    risk_analyzer.py   database.py │
                  │  validate +    rule-based rating  parameterised│
                  │  Nmap -sT -F   HIGH/MED/LOW       SQLite      │
                  └────────┼──────────────────────────────┼───────┘
                           ▼                              ▼
                     Nmap binary              instance/aegis_scanner.db
```

`POST /api/scan` validates the target, runs the scan, rates each open port, persists the
result inside a transaction, and returns the record with its `scan_id`. Every other
endpoint reads from the same database — nothing is recomputed from a live scan.

The assistant endpoint accepts a short scan-goal description. OpenAI returns a profile ID
from a strict schema; the application maps that ID to fixed Nmap arguments. Model output is
never executed as a command. Available profiles are `quick` (`-sT -F`), `common_tcp`
(`-sT -p 1-1000`), `all_tcp` (`-sT -p-`), and `service_detection` (`-sT -sV -F`). The last
two can take longer or send additional probes. The operator reviews and applies a suggestion
before starting a scan.

### Risk model

Ratings come from an explicit table in [`risk_analyzer.py`](risk_analyzer.py), matched by
port number first and service name second, with an unknown service falling back to `LOW`:

| Rating | Ports | Rationale |
| --- | --- | --- |
| `HIGH` | 21, 23, 445, 3306, 3389 | Cleartext legacy protocols (FTP, Telnet) or high-value services that should not face a network directly (SMB, MySQL, RDP). |
| `MEDIUM` | 22, 80, 135 | Exposed but defensible — needs hardening review (SSH keys, HTTPS migration, RPC restriction). |
| `LOW` | 443, everything else | Encrypted by design, or unrecognised and requiring manual confirmation. |

A scan's overall rating is the highest rating among its findings.

## Project structure

```text
.
├── app.py                 # Flask routes, security headers, rate limiting
├── scanner.py             # Target validation and the Nmap invocation
├── ai_assistant.py        # OpenAI profile recommendation and response validation
├── risk_analyzer.py       # Deterministic risk rules and Security Score calculator
├── service_fingerprints.py # Educational service fingerprint knowledge base
├── export_service.py      # Unified multi-format report exporter (PDF, CSV, JSON, TXT)
├── comparator.py          # Scan comparison (exposure diff) engine
├── database.py            # SQLite schema and parameterised queries
├── test_app.py            # 43 automated regression tests (no live scan, Nmap mocked)
├── requirements.txt       # Python dependencies
├── package.json           # Tailwind CSS v4 build toolchain
├── templates/
│   └── index.html         # Single-page dashboard
├── static/
│   ├── css/src.css        # Tailwind source  ← edit this
│   ├── css/style.css      # Tailwind build output (generated, committed)
│   ├── js/script.js       # Dashboard logic
│   ├── fonts/             # Self-hosted fonts (no CDN, for strict CSP)
│   └── logo.png
├── design/                # UI design references and mockups
└── instance/              # Runtime SQLite database (gitignored)
```

## Getting started

### Prerequisites

- **Python 3.12+**
- **Nmap** — [download](https://nmap.org/download.html). On Windows the default install
  path (`C:\Program Files (x86)\Nmap`) is added to `PATH` automatically at import time.
- **Node.js 20+** — only if you intend to modify the styling.

### Installation

```bash
git clone https://github.com/deepakcybersecurity/Network-Security-Analyser.git
cd Network-Security-Analyser
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

```bash
source venv/bin/activate
```

On Windows, activate with `venv\Scripts\activate` instead. Then install dependencies:

```bash
pip install -r requirements.txt
```

The application reads configuration from process environment variables. Copying
`.env.example` does not load it automatically; set the variables in the same shell or
service environment that starts Flask. For example, in PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-6-astra"
python app.py
```

### Running

```bash
python app.py
```

The dashboard is served at <http://127.0.0.1:5000/>. The database is created on first run
at `instance/aegis_scanner.db`.

### Configuration

These variables are read from the environment. The API key is required only for AI
recommendations; scans can still use the default quick profile without it.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | random `os.urandom(32)` per start | Flask session signing key. Set explicitly for any real deployment. |
| `FLASK_DEBUG` | `false` | Set to `true` only for local debugging — it exposes the Werkzeug interactive console. |
| `OPENAI_API_KEY` | unset | Enables AI scan recommendations. Keep it server-side; never put it in browser code. |
| `OPENAI_MODEL` | `gpt-6-astra` | OpenAI model used for recommendations. |

### Modifying the styling

`static/css/style.css` is generated by Tailwind from `static/css/src.css` and committed so
the app runs without a Node toolchain. If you change `src.css`, rebuild and commit the
output — CI verifies the two stay in sync.

```bash
npm install
```

```bash
npm run build:css
```

Use `npm run dev:css` to rebuild on change while developing.

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Dashboard |
| `POST` | `/api/scan` | Scan and persist a target. Body: `{ "target": "127.0.0.1" }`. Limited to 10 req/min per IP. |
| `POST` | `/api/assistant/recommend` | Recommend a reviewed scan profile from `{ "need": "..." }`. Limited to 20 req/min per IP. |
| `GET` | `/api/history` | Recent scans, newest first |
| `DELETE` | `/api/history` | Permanently clear all scans and findings |
| `GET` | `/api/scan/<scan_id>` | Saved scan metadata plus individual findings with deterministic remediation playbook |
| `GET` | `/api/stats` | Database-backed totals by risk level |
| `GET` | `/api/stats/visualizations` | Aggregated datasets for SVG visualizations (risk distribution, top targets, scan timeline) |
| `GET` | `/api/scan/compare` | Exposure diff comparison between two historical scans of the same target (`?base_id=1&target_id=2`) |
| `GET` | `/api/ai/analyze/<scan_id>` | Retrieve cached post-scan AI Security Analyst report |
| `POST` | `/api/ai/analyze/<scan_id>` | Run post-scan AI Security Analyst evaluation with offline heuristic fallback |
| `GET` | `/api/scan/<scan_id>/export` | Multi-format export dispatcher: `?format=txt` (default), `?format=pdf` (ReportLab executive PDF), `?format=csv` (injection-safe CSV), `?format=json` (schema 1.0) |

<details>
<summary><strong>Example</strong> — <code>POST /api/scan</code></summary>

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

```json
{
  "target": "127.0.0.1",
  "status": "success",
  "scan_id": 1,
  "overall_risk": "MEDIUM",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "risk": "MEDIUM",
      "reason": "HTTP web server is exposed. Traffic is unencrypted, meaning credentials or session tokens could be intercepted in transit. Consider migrating to HTTPS."
    }
  ]
}
```

</details>

## Testing

The suite patches `app.scan_target` and uses a temporary SQLite database, so it never
touches the network and needs no Nmap binary:

```bash
python -m unittest -v test_app.py
```

Forty-three automated tests cover request validation, malformed JSON handling, persistence across
history/details/stats/export, security headers, secret-key configuration, rate-limit
enforcement, history deletion, AI analysis caching and offline fallback, visual risk dashboard statistics,
exposure diff comparison across 12 edge cases, deterministic remediation playbooks, multi-format exports
(PDF, CSV, JSON, TXT), CSV formula injection defenses, Service Fingerprint knowledge cards, and the
deterministic Security Score (0 to 100) scoring heuristic. CI runs them on Python 3.12 and 3.13 across Ubuntu and
Windows.

For a live end-to-end check, scan `127.0.0.1` from the dashboard. An invalid target such as
`invalid;target` is rejected with HTTP 400.

## Security architecture

| Control | Implementation |
| --- | --- |
| **Input validation** | Regex allowlist `^[a-zA-Z0-9.:-]+$`, 1–253 character bounds, leading-hyphen and leading/trailing-dot rejection, and DNS resolution — all before Nmap runs. |
| **Command injection** | Nmap invoked through `python-nmap` with fixed arguments. No `shell=True`, no shell string concatenation anywhere. |
| **SQL injection** | Every statement parameterised, with `PRAGMA foreign_keys = ON` on all connections. |
| **XSS** | DOM built with `textContent` only; risk labels validated against a client-side allowlist; CSP forbids inline and external script. |
| **Content Security Policy** | `default-src 'self'` with `object-src 'none'` and `base-uri 'self'`. Fonts and CSS are self-hosted specifically so no CDN exception is needed. |
| **HTTP hardening** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Cache-Control: no-store` on API routes. Server banner replaced with `Aegis-Scanner`. |
| **Error sanitisation** | Exceptions and Nmap failures are logged server-side via `logging`; clients receive generic JSON messages that leak no paths, versions, or stack traces. |
| **Rate limiting** | `POST /api/scan` capped at 10 requests/minute per IP via Flask-Limiter, returning sanitised JSON on 429. |
| **Debug mode** | `FLASK_DEBUG` defaults to `false`, so the Werkzeug interactive debugger is never exposed unintentionally. |
| **Data isolation** | The runtime database lives in `instance/` and is gitignored, along with `scans/` and every `.env` file. |
| **Supply chain** | Pinned dependency ranges, Dependabot updates for pip/npm/Actions, and weekly CodeQL analysis with `security-extended`. |

To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Known limitations

- Flask's development server is used as-is. Any deployment beyond localhost needs a
  production WSGI server and an explicit `SECRET_KEY`.
- Rate limiting uses in-memory storage, so counters reset on restart and are not shared
  across processes. Point Flask-Limiter at Redis for a multi-worker deployment.
- There is no authentication. The app binds to `127.0.0.1` and assumes a single trusted
  local operator.
- Risk ratings are a static educational heuristic, not a vulnerability assessment. They do
  not consider version, patch level, or configuration.

## Contributing

Issues and pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup and expectations.

## Ethical use

Use this tool only on systems and networks you own or where you hold explicit
authorisation to perform security testing. Unauthorised port scanning is a criminal
offence in many jurisdictions, may disrupt the systems it touches, and will alert security
monitoring. You are responsible for how you use it.

## License

Released under the [MIT License](LICENSE).
