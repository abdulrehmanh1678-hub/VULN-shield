# VulnShield — AI-Powered Agentic Security Scanner

A full-stack security analysis platform that scans source code for common
vulnerabilities using an agentic pipeline with optional AI enrichment.
**It runs entirely on Vercel — no separate backend required.**

## Features

- **Code Editor** — paste code and run instant static analysis
- **Multi-File Upload** — batch scan up to 10 source files
- **GitHub Scanner** — scan public repositories (via GitHub API, no clone)
- **Agentic Pipeline** — recon → module routing → static rules → AI report
- **13 Vulnerability Rules** — SQLi, XSS, secrets, weak crypto, command injection, JWT, path traversal, file upload, SSRF, insecure deserialization, CORS wildcard, open redirect, NoSQL injection
- **Multi-Language** — rules and recon understand both JavaScript/Express and Python (Flask/Django/FastAPI) idioms
- **AI Reports** — executive summaries from a **local model (Ollama/Qwen)**, the OpenAI serverless function, or a built-in static engine — switchable in-app
- **Scan History** — saved in the browser (localStorage) with JSON / PDF export

## Architecture

The scanner runs **in the browser** — recon, all 8 rules, history, and export
need no server. AI enrichment is the only server-side piece, handled by a small
**Vercel Serverless Function** (`client/api/report.js`) that keeps the OpenAI key
private. The original Express API under `server/` remains for optional
self-hosting but is not needed for the Vercel deployment.

```
client/
   src/lib/scanner.js   # static rules engine + agent orchestrator (browser)
   src/lib/report.js    # AI report router: Ollama / serverless / static fallback
   src/lib/aiConfig.js  # AI provider config (localStorage + Vite env) + Ollama probe
   src/lib/aiPrompt.js  # shared system prompt, schema, and robust JSON parser
   src/lib/github.js    # GitHub API repo scanner (browser)
   src/lib/history.js   # localStorage scan history
   src/lib/export.js    # JSON + print-to-PDF export
   api/report.js        # Vercel serverless function (OpenAI)
server/                 # optional self-hosted Express API (SQLite, git clone)
```

## Deploy to Vercel (recommended)

1. Import the GitHub repo at [vercel.com/new](https://vercel.com/new).
2. **Project Settings → Root Directory:** `client`
   (Framework: **Vite** · Build: `npm run build` · Output: `dist`)
3. *(Optional, for AI reports)* **Settings → Environment Variables** → add
   `OPENAI_API_KEY` = your key. Optionally `OPENAI_MODEL` (default `gpt-4o-mini`).
4. **Deploy.** The header shows **Scan Engine Ready**, plus **AI Reports Active**
   when the key is set.

> Without `OPENAI_API_KEY`, scanning still works fully — reports use the built-in
> static engine (risk scoring, OWASP/CWE references, remediation) instead of AI.

GitHub scanning reads public repos via the GitHub API + raw CDN from the browser.
Unauthenticated GitHub API is rate-limited (~60/hour per IP); scanning is capped
at 40 source files per repo.

## Run fully local with Ollama (Qwen) — no cloud, no API key

VulnShield can generate its AI reports from a model running entirely on your own
machine via [Ollama](https://ollama.com). Nothing leaves your computer.

1. **Install Ollama** (ollama.com/download), then pull a model — a code-savvy one
   like Qwen works well:
   ```bash
   ollama pull qwen2.5-coder        # or: qwen2.5, llama3.1, mistral, etc.
   ```
2. **Allow the browser to call Ollama.** The app (a web page) calls Ollama
   cross-origin, so start the Ollama server with browser origins allowed:
   ```bash
   # macOS/Linux
   OLLAMA_ORIGINS=* ollama serve
   # Windows (PowerShell)
   $env:OLLAMA_ORIGINS="*"; ollama serve
   ```
   (Leave this running. On a default install Ollama already listens on
   `http://localhost:11434`.)
3. **Start the app** and select the local engine:
   ```bash
   cd client && npm install && npm run dev   # http://localhost:5173
   ```
   Click the **AI** badge in the header → choose **Local · Ollama** → set the model
   (`qwen2.5-coder`) → **Test connection** → **Save**. Run a scan and the report is
   produced by your local model. The badge reads **AI: Local (Ollama)**.

You can also set defaults at build time without touching the UI:

```bash
# client/.env.local
VITE_AI_PROVIDER=ollama
VITE_OLLAMA_URL=http://localhost:11434
VITE_OLLAMA_MODEL=qwen2.5-coder
```

> If anything is unreachable, the report transparently falls back to the static
> engine, so a scan never fails just because the model is offline.

## Local Development

```bash
# Frontend only (reports use the static engine unless you configure Ollama/OpenAI above)
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

If you upgrade Node, rebuild the one native dependency: `cd server && npm rebuild better-sqlite3`.

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

## Docker (self-hosted full stack)

```bash
docker compose up --build -d        # http://localhost:5000
```

## Tech Stack

- **Frontend:** React 19, Vite, Lucide Icons
- **AI:** Local Ollama (Qwen by default) or OpenAI GPT (`gpt-4o-mini`) — both optional, static fallback built in
- **Scanner:** Regex-based static analysis with agentic orchestration (browser), multi-language (JS + Python)
- **Optional backend:** Express 5, better-sqlite3, multer, pdfkit

## License

MIT
