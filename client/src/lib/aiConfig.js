/**
 * AI provider configuration for report generation.
 *
 * Resolution order: localStorage override (set via the in-app AI Settings panel)
 * → Vite build-time env defaults → hard-coded defaults. This lets a user switch
 * between a fully-local Ollama model and the hosted serverless function without
 * rebuilding.
 *
 * Providers:
 *   'auto'       – try serverless (OpenAI) first, then local Ollama, then static
 *   'ollama'     – local model via Ollama (fully offline)
 *   'serverless' – Vercel /api/report (OpenAI)
 *   'static'     – no LLM; rule-based enriched report only
 */

const LS_KEY = 'vs-ai-config';

const DEFAULTS = {
  provider: import.meta.env.VITE_AI_PROVIDER || 'auto',
  ollamaUrl: (import.meta.env.VITE_OLLAMA_URL || 'http://localhost:11434').replace(/\/+$/, ''),
  ollamaModel: import.meta.env.VITE_OLLAMA_MODEL || 'qwen2.5-coder',
  // OpenAI: a key entered here lets the browser call OpenAI directly (works in
  // local dev). If left blank, the 'serverless' provider uses the Vercel function
  // instead, which keeps the key server-side.
  openaiKey: import.meta.env.VITE_OPENAI_API_KEY || '',
  openaiModel: import.meta.env.VITE_OPENAI_MODEL || 'gpt-4o-mini',
};

export function getAiConfig() {
  let stored = {};
  try {
    stored = JSON.parse(localStorage.getItem(LS_KEY) || '{}');
  } catch {
    // malformed JSON — fall back to defaults
  }
  const cfg = { ...DEFAULTS, ...stored };
  cfg.ollamaUrl = String(cfg.ollamaUrl).replace(/\/+$/, '');
  return cfg;
}

export function setAiConfig(patch) {
  const next = { ...getAiConfig(), ...patch };
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(next));
  } catch {
    // localStorage unavailable (private mode) — config simply won't persist.
  }
  return next;
}

/**
 * Probe a running Ollama instance. Returns the list of locally-installed model
 * names, or throws if it can't be reached (so the UI can show a clear error).
 */
export async function checkOllama(url = getAiConfig().ollamaUrl) {
  const base = String(url).replace(/\/+$/, '');
  const res = await fetch(`${base}/api/tags`, { method: 'GET' });
  if (!res.ok) throw new Error(`Ollama responded ${res.status}`);
  const data = await res.json();
  return (data.models || []).map(m => m.name);
}
