# VulnShield — AI-Powered Agentic Security Scanner

VulnShield is a security analysis platform that scans source code for common
vulnerabilities using a multi-phase **agentic pipeline** and turns the raw
findings into a professional, human-readable audit report — optionally enriched
by an LLM.

You give it code (paste a snippet, upload files, or point it at a public GitHub
repo); it detects the language and framework, runs a battery of vulnerability
rules, and produces an executive summary, a risk score, per-finding remediation
guidance, and exportable evidence (JSON / PDF).

**The entire scanner runs in the browser.** It is deployed as a static site plus
a single serverless function on Vercel — no always-on backend is required. A
legacy Express + SQLite backend lives under `server/` for optional self-hosting,
but the hosted app does not use it.

> Portfolio project demonstrating agentic pipelines, static analysis (SAST), and
> AI-enhanced security reporting.

---

## Table of Contents

- [Key Features](#key-features)
- [How It Works (The Pipeline)](#how-it-works-the-pipeline)
- [Vulnerability Rules](#vulnerability-rules)
- [The AI Report System](#the-ai-report-system)
- [Using the App](#using-the-app)
- [Architecture & Project Structure](#architecture--project-structure)
- [Result Data Model](#result-data-model)
- [Deploy to Vercel](#deploy-to-vercel-recommended)
- [Run Fully Local with Ollama](#run-fully-local-with-ollama-no-cloud-no-api-key)
- [Local Development](#local-development)
- [Environment Variables](#environment-variables)
- [Self-Hosted API (server/ only)](#self-hosted-api-endpoints-server-only)
- [Docker](#docker-self-hosted-full-stack)
- [Tech Stack](#tech-stack)
- [Limitations & Notes](#limitations--notes)
- [License](#license)

---

## Key Features

- **Three input modes** — paste into the code editor, upload up to 10 files for
  batch scanning, or scan any public GitHub repository.
- **Agentic pipeline** — Recon → Module Routing → Static Analysis → AI Report,
  with a live agent log of every step.
- **13 vulnerability rules** — SQL injection, XSS, hardcoded secrets, weak
  crypto, command injection, unsafe JWT decode, path traversal, insecure file
  upload, SSRF, insecure deserialization, wildcard CORS, open redirect, and
  NoSQL injection.
- **Multi-language detection** — recon and rules understand both
  JavaScript/TypeScript (Express) and Python (Flask / Django / FastAPI) idioms.
- **Switchable AI engine** — generate reports from a **local Ollama model**, the
  **OpenAI serverless function**, or a built-in **static engine** — chosen in-app
  and persisted to your browser. Every path falls back to static so a scan never
  fails because a model is offline.
- **Rich reports** — executive summary, 0–100 risk score and label, OWASP/CWE
  references, prioritized actions, secure-architecture recommendations, and
  compliance notes.
- **Scan history & export** — every scan is saved in the browser (localStorage)
  and can be exported as JSON or printed to PDF.
- **Polished UX** — glassmorphism design system, light/dark theme,
  severity filter chips, OWASP Top 10 coverage row, copy buttons, risk gauge,
  and a `Ctrl+Enter` scan shortcut.

---

## How It Works (The Pipeline)

The "agent" runs four phases entirely in the browser
(`client/src/lib/scanner.js`). Each phase appends to an agent log that you can
inspect in the **🖥 Agent Log** tab.

### 1. Reconnaissance (`runRecon`)
Inspects the code to determine:
- **Language** — JavaScript/TypeScript, Python, Go, Java, or C#. Detection uses
  language-specific tokens; a bare `import` is treated as ambiguous so Python is
  not misclassified as JS.
- **Framework** — React, Express, Flask, or Django.
- **Entry points** — HTTP route definitions across frameworks
  (`app.get(...)`, Flask/FastAPI `@app.route` decorators, Django `urlpatterns`,
  and `def handler(req, res)` style handlers).

### 2. Module Routing
Selects which rules to run based on recon results:
- **Always-on (language-agnostic):** Hardcoded Secrets, Weak Cryptography,
  Wildcard CORS.
- **JavaScript/TypeScript:** adds SQLi, XSS, Command Injection, JWT, Path
  Traversal, Insecure Upload, SSRF, Open Redirect, NoSQL Injection, Insecure
  Deserialization.
- **Python:** adds SQLi, XSS (templates), Command Injection, JWT, Path Traversal,
  SSRF, Open Redirect, Insecure Deserialization.
- **Unknown/other:** falls back to enabling all rules.

### 3. Static Analysis (Execution)
Runs each selected rule's regex against every line of code. Each match becomes a
**finding** carrying its severity, CVSS score, file, line number, the matched
evidence line, a description, the impact, a fix, and a secure-code example.

### 4. Aggregation
Combines all findings into a single result object with a summary (counts,
language, framework, entry-point count, timestamp) and the full agent log. For
multi-file and GitHub scans, every file is scanned individually and the findings
are merged (`scanFiles` / `scanGitHubRepo`).

After the pipeline, `generateReport` (`client/src/lib/report.js`) enriches the
result into the final audit report — see [The AI Report System](#the-ai-report-system).

---

## Vulnerability Rules

All 13 rules are defined in `client/src/lib/scanner.js`. Patterns match both
JS/Express and Python idioms where applicable.

| ID | Title | Severity | CVSS | OWASP / CWE |
|----|-------|----------|------|-------------|
| `SEC-SQLI` | SQL Injection | High | 8.2 | A03 Injection / CWE-89 |
| `SEC-XSS-DOM` | DOM / template XSS | Medium | 6.1 | A03 Injection / CWE-79 |
| `SEC-SECRET` | Hardcoded Secret / API Key | Critical | 9.8 | A02 Crypto Failures / CWE-312 |
| `SEC-WEAK-CRYPTO` | Weak Crypto (MD5/SHA-1) | Medium | 5.9 | A02 Crypto Failures / CWE-327 |
| `SEC-CMD-INJ` | Command Injection / RCE | Critical | 9.8 | A03 Injection / CWE-78 |
| `SEC-JWT-UNSAFE` | Unsafe JWT Decode | High | 7.5 | A07 Auth Failures / CWE-347 |
| `SEC-PATH-TRAVERSAL` | Path Traversal | High | 7.5 | A01 Broken Access / CWE-22 |
| `SEC-FILE-UPLOAD` | Insecure File Upload | High | 8.0 | A04 Insecure Design / CWE-434 |
| `SEC-SSRF` | Server-Side Request Forgery | High | 7.5 | A10 SSRF |
| `SEC-DESERIAL` | Insecure Deserialization | Critical | 9.8 | A08 Integrity Failures |
| `SEC-CORS-WILD` | Permissive CORS | Medium | 5.3 | A05 Misconfiguration |
| `SEC-OPEN-REDIRECT` | Open Redirect | Medium | 6.1 | A01 Broken Access |
| `SEC-NOSQL` | NoSQL Injection | High | 8.1 | A03 Injection |

> These are **regex-based heuristics** for fast, dependency-free static analysis.
> They are designed to surface likely issues for review, not to replace a full
> dynamic analysis or manual audit.

---

## The AI Report System

After the static scan, the findings are turned into a polished report. The engine
is selected in the in-app **AI Settings** panel (click the AI badge in the
header), persisted to `localStorage`, with defaults from Vite build-time env.
Configuration is resolved in `client/src/lib/aiConfig.js`; routing and fallback
live in `client/src/lib/report.js`.

**Providers:**

| Provider | What it does | Where it runs |
|----------|--------------|---------------|
| `serverless` | Calls the Vercel function `client/api/report.js`, which proxies OpenAI (`gpt-4o-mini` by default) with the key kept server-side. | Vercel serverless |
| `ollama` | Calls a local Ollama model (`http://localhost:11434`, default `qwen2.5-coder`). Fully offline. | Your machine |
| `auto` | Tries serverless first, then Ollama. | — |
| `static` | No LLM — builds the report from rules in the browser. | Browser |

**Automatic fallback:** if the chosen LLM is unavailable (no key, offline, CORS,
request error), `generateReport` transparently falls back to the static engine
(`buildStaticReport`), so a report always renders.

**What the report contains** (same schema for every provider, defined in
`client/src/lib/aiPrompt.js` / `client/api/report.js`):
- `executiveSummary` — 2–3 sentence health overview
- `riskScore` (0–100) and `riskLabel` (Critical / High / Medium / Low / Secure)
- `findings[]` — each enriched with explanation, impact, fix, secure-code
  example, and OWASP/CWE references
- `prioritizedActions[]` — the top immediate actions
- `secureArchitectureRecommendations[]`
- `complianceNotes` — PCI-DSS / OWASP / GDPR relevance

The static engine computes the risk score from weighted severities
(Critical 40 / High 20 / Medium 10 / Low 5, capped at 100).

---

## Using the App

1. **Pick an input tab** (left panel):
   - **Code Editor** — paste source code. Scan with the button or `Ctrl+Enter`.
   - **File Upload** — drag in up to 10 files; they are scanned and aggregated.
   - **GitHub Repo** — paste a public repo HTTPS URL.
2. **Run the scan.** The progress tracker shows the five pipeline steps.
3. **Read the results** (right panel), across three sub-tabs:
   - **🔍 Findings** — filterable by severity, with copy buttons and an OWASP
     Top 10 coverage row.
   - **🤖 AI Report** — executive summary, risk gauge, and remediation guidance.
   - **🖥 Agent Log** — the full step-by-step pipeline trace.
4. **Export / revisit** — download JSON or PDF, or reopen any earlier scan from
   the **History** sidebar (stored in your browser).

The header badges show **Scan Engine Ready** and the active AI mode
(**AI: Local (Ollama)** / **AI: Cloud** / **AI: Static Mode**).

---

## Architecture & Project Structure

The scanner, history, and export are 100% browser-side. The only server-side
piece is AI enrichment, handled by one Vercel serverless function that keeps the
OpenAI key private.

```
client/
  src/
    App.jsx                  # main layout, tabs, scan orchestration, Ctrl+Enter
    index.css                # design system, animations, responsive grid
    api.js                   # resolves API base URL
    components/
      CodeEditor.jsx         # paste/edit + sample loader
      FileUploader.jsx       # multi-file upload
      GitHubScanner.jsx      # repo URL input + progress
      ProgressTracker.jsx    # 5-step pipeline progress
      ResultsViewer.jsx      # findings list, severity filters, OWASP coverage
      AIReportViewer.jsx     # report + risk score gauge
      AgentTerminal.jsx      # agent log view
      HistorySidebar.jsx     # past scans (localStorage)
      AISettings.jsx         # provider picker (Ollama/serverless/static)
      Toast.jsx              # notifications
    lib/
      scanner.js             # static rules engine + agent orchestrator (browser)
      report.js              # AI report router: Ollama / serverless / static
      aiConfig.js            # provider config (localStorage + Vite env) + probe
      aiPrompt.js            # shared system prompt, schema, JSON parser
      github.js              # GitHub API repo scanner (clone-free)
      history.js             # localStorage scan history
      export.js              # JSON + print-to-PDF export
      vulnMeta.js            # severity/category metadata for the UI
  api/
    report.js                # Vercel serverless function (OpenAI proxy)
  vercel.json                # excludes /api from the SPA rewrite

server/                      # optional self-hosted Express API (not used on Vercel)
  server.js                  # Express app
  database.js                # SQLite (better-sqlite3) scans table
  githubScanner.js           # git-clone-based repo scanner
  pdfGenerator.js            # server-side PDF
  agent/                     # original orchestrator, tools, AI reporter, prompts
  routes/                    # scan, github, export endpoints
```

**GitHub scanning** (`client/src/lib/github.js`) is clone-free: it reads repo
metadata and the recursive file tree from the GitHub API, then fetches each
source file from `raw.githubusercontent.com` (CORS-enabled, not API-rate-limited)
and runs the same in-browser scanner. It is capped at **40 source files** and
**200 KB per file**, skipping `node_modules`, build output, vendored dirs, etc.

---

## Result Data Model

A scan result (saved to history and passed to the report layer) looks like:

```jsonc
{
  "success": true,
  "filename": "pasted_code.js",      // or joined file names / repo URL
  "scanId": "uuid",
  "summary": {
    "totalVulnerabilities": 3,
    "language": "JavaScript/TypeScript",
    "framework": "Express (Node.js)",
    "entryPointsCount": 2,
    "timestamp": "ISO-8601"
  },
  "recon": { "language": "...", "framework": "...", "entryPoints": [ ... ] },
  "findings": [
    {
      "id": "SEC-SQLI-12", "title": "Potential SQL Injection",
      "category": "SQL Injection", "severity": "High", "cvss": 8.2,
      "file": "pasted_code.js", "line": 12,
      "evidence": "db.query(\"SELECT ... \" + input)",
      "description": "...", "danger": "...", "fix": "...", "safeCode": "..."
    }
  ],
  "agentLogs": [ { "timestamp": "...", "step": "RECON_START", "message": "..." } ],
  "aiReport": { /* the enriched report object */ },
  "aiGenerated": true
}
```

---

## Deploy to Vercel (recommended)

1. Import the GitHub repo at [vercel.com/new](https://vercel.com/new).
2. **Project Settings → Root Directory:** `client`
   (Framework: **Vite** · Build: `npm run build` · Output: `dist`)
3. *(Optional, for AI reports)* **Settings → Environment Variables** → add
   `OPENAI_API_KEY` = your key. Optionally `OPENAI_MODEL` (default `gpt-4o-mini`).
4. **Deploy.** The header shows **Scan Engine Ready**, plus an active AI badge
   when the key is set.

> Without `OPENAI_API_KEY`, scanning still works fully — reports use the built-in
> static engine (risk scoring, OWASP/CWE references, remediation) instead of AI.

GitHub scanning reads public repos via the GitHub API + raw CDN from the browser.
Unauthenticated GitHub API is rate-limited (~60/hour per IP); scanning is capped
at 40 source files per repo.

---

## Run Fully Local with Ollama (no cloud, no API key)

VulnShield can generate its AI reports from a model running entirely on your own
machine via [Ollama](https://ollama.com). Nothing leaves your computer.

1. **Install Ollama** (ollama.com/download), then pull a model — a code-savvy one
   like Qwen works well:
   ```bash
   ollama pull qwen2.5-coder        # or: qwen2.5, llama3.1, mistral, etc.
   ```
2. **Allow the browser to call Ollama.** The app (a web page) calls Ollama
   cross-origin, so start the server with browser origins allowed:
   ```bash
   # macOS/Linux
   OLLAMA_ORIGINS=* ollama serve
   # Windows (PowerShell)
   $env:OLLAMA_ORIGINS="*"; ollama serve
   ```
   (Leave this running. By default Ollama listens on `http://localhost:11434`.)
3. **Start the app** and select the local engine:
   ```bash
   cd client && npm install && npm run dev   # http://localhost:5173
   ```
   Click the **AI** badge in the header → choose **Local · Ollama** → set the model
   (`qwen2.5-coder`) → **Test connection** → **Save**. Run a scan and the report is
   produced by your local model. The badge reads **AI: Local (Ollama)**.

Set defaults at build time without touching the UI:

```bash
# client/.env.local
VITE_AI_PROVIDER=ollama
VITE_OLLAMA_URL=http://localhost:11434
VITE_OLLAMA_MODEL=qwen2.5-coder
```

> If anything is unreachable, the report transparently falls back to the static
> engine, so a scan never fails just because the model is offline.

---

## Local Development

```bash
# Frontend only (reports use the static engine unless you configure Ollama/OpenAI)
cd client && npm install && npm run dev   # http://localhost:5173
```

To develop the serverless AI function locally, use the Vercel CLI:

```bash
npm i -g vercel
cd client && vercel dev
```

### Optional: run the legacy full Express backend

```bash
npm run install:all
copy server\.env.example server\.env   # add OPENAI_API_KEY (optional)
npm run dev                             # server :5000 + client :5173
```

If you upgrade Node, rebuild the one native dependency:
`cd server && npm rebuild better-sqlite3`.

---

## Environment Variables

| Variable | Where | Required | Description |
|----------|-------|----------|-------------|
| `OPENAI_API_KEY` | Vercel / server | No | Enables AI-enriched reports. Without it, static reports are used. |
| `OPENAI_MODEL` | Vercel / server | No | Override model (default `gpt-4o-mini`). |
| `GEMINI_API_KEY` | server only | No | Google Gemini alternative (self-hosted backend only). |
| `VITE_AI_PROVIDER` | client build | No | Default AI engine: `auto` (default), `ollama`, `serverless`, or `static`. Overridable in-app. |
| `VITE_OLLAMA_URL` | client build | No | Local Ollama base URL (default `http://localhost:11434`). |
| `VITE_OLLAMA_MODEL` | client build | No | Local Ollama model name (default `qwen2.5-coder`). |
| `OLLAMA_ORIGINS` | Ollama server | For local AI | Set to `*` (or your dev origin) so the browser can reach Ollama cross-origin. |
| `VITE_API_URL` | client build | No | Only to target a self-hosted Express API instead of the serverless function. |
| `PORT` | server | No | Self-hosted server port (default: 5000). |
| `NODE_ENV` | server | No | Set to `production` for deployed environments. |

---

## Self-Hosted API Endpoints (server/ only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Scan pasted code or uploaded files |
| GET | `/api/scan/history` | List past scans |
| GET | `/api/scan/:id` | Get scan details |
| DELETE | `/api/scan/:id` | Delete a scan |
| POST | `/api/github` | Scan a public GitHub repo |
| GET | `/api/export/:id/pdf` | Download PDF report |
| GET | `/api/export/:id/json` | Download JSON report |

The Vercel deployment uses a single serverless endpoint, `POST /api/report`
(plus `GET /api/report` to probe whether AI is configured).

---

## Docker (self-hosted full stack)

```bash
docker compose up --build -d        # http://localhost:5000
```

---

## Tech Stack

- **Frontend:** React 19, Vite, Lucide Icons, CSS glassmorphism design system
- **AI:** Local Ollama (Qwen by default) or OpenAI GPT (`gpt-4o-mini`) — both
  optional, with a built-in static fallback
- **Scanner:** Regex-based static analysis with agentic orchestration, running in
  the browser, multi-language (JavaScript/TypeScript + Python)
- **Serverless:** one Vercel function (`client/api/report.js`) proxying OpenAI
- **Optional backend:** Express 5, better-sqlite3, multer, pdfkit

---

## Limitations & Notes

- Rules are **heuristic regex patterns** — expect false positives/negatives;
  treat results as leads for review, not a definitive audit.
- GitHub scanning is limited to **public** repos, **40 files**, **200 KB/file**,
  and is subject to GitHub's unauthenticated rate limit (~60 requests/hour/IP).
- History and configuration live in the browser's `localStorage` — they are
  per-device and cleared if you clear site data.
- Local Ollama reports require `OLLAMA_ORIGINS=*` so the browser can reach the
  model cross-origin.

---

## License

MIT
