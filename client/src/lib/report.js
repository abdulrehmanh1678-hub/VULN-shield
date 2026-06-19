/**
 * Report generation (browser-side).
 * Tries the Vercel serverless function /api/report (OpenAI-backed) first, and
 * falls back to a fully client-side enriched static report when AI is
 * unavailable (no key configured, offline, or request fails).
 */

import { apiUrl } from '../api';
import { getAiConfig } from './aiConfig';
import { SYSTEM_PROMPT, buildPrompt, parseReportJson } from './aiPrompt';

const REFERENCES = {
  'SEC-SQLI': ['OWASP A03:2021 – Injection', 'CWE-89: SQL Injection', 'https://owasp.org/www-community/attacks/SQL_Injection'],
  'SEC-XSS-DOM': ['OWASP A03:2021 – Injection (XSS)', 'CWE-79: Cross-site Scripting', 'https://owasp.org/www-community/attacks/xss/'],
  'SEC-SECRET': ['OWASP A02:2021 – Cryptographic Failures', 'CWE-312: Cleartext Storage of Sensitive Information'],
  'SEC-WEAK-CRYPTO': ['OWASP A02:2021 – Cryptographic Failures', 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'],
  'SEC-CMD-INJ': ['OWASP A03:2021 – Injection (Command)', 'CWE-78: OS Command Injection'],
  'SEC-JWT-UNSAFE': ['OWASP A07:2021 – Identification and Authentication Failures', 'CWE-347: Improper Verification of Cryptographic Signature'],
  'SEC-PATH-TRAVERSAL': ['OWASP A01:2021 – Broken Access Control', 'CWE-22: Path Traversal'],
  'SEC-FILE-UPLOAD': ['OWASP A04:2021 – Insecure Design', 'CWE-434: Unrestricted Upload of File with Dangerous Type']
};

function getReferences(ruleId) {
  const ruleBase = ruleId.replace(/-\d+$/, '');
  return REFERENCES[ruleBase] || ['OWASP Top 10 2021', 'CWE Reference Available'];
}

function getPrioritizedActions(findings) {
  const actions = [];
  const hasCritical = findings.some(f => f.severity === 'Critical');
  const hasHigh = findings.some(f => f.severity === 'High');
  const hasSecret = findings.some(f => f.id.startsWith('SEC-SECRET'));
  const hasSQLi = findings.some(f => f.id.startsWith('SEC-SQLI'));
  const hasXSS = findings.some(f => f.id.startsWith('SEC-XSS'));
  const hasCMD = findings.some(f => f.id.startsWith('SEC-CMD'));

  if (hasSecret) actions.push('🚨 Immediately rotate all exposed API keys, passwords, and tokens. Move them to environment variables.');
  if (hasCMD) actions.push('🚨 Eliminate all dynamic shell command execution from user-controlled inputs to prevent Remote Code Execution.');
  if (hasSQLi) actions.push('🔴 Replace all raw SQL string concatenation with parameterized queries or a trusted ORM.');
  if (hasXSS) actions.push('🔴 Sanitize all user-generated HTML output using DOMPurify before rendering.');
  if (hasCritical || hasHigh) actions.push('🔴 Conduct an immediate security code review of all high and critical findings before any production deployment.');
  actions.push('🟡 Run a comprehensive dependency audit (npm audit / pip-audit) to identify known CVEs in third-party packages.');
  actions.push('🟡 Add security headers middleware (helmet.js) to all Express responses to prevent common browser attacks.');
  actions.push('🟢 Integrate this security scanner into your CI/CD pipeline to catch issues on every commit.');

  return actions.slice(0, 6);
}

/** Build an enriched report fully in the browser (no AI). */
export function buildStaticReport(scanData) {
  const { findings, recon } = scanData;

  const severityWeights = { critical: 40, high: 20, medium: 10, low: 5 };
  let riskScore = 0;
  findings.forEach(f => { riskScore += severityWeights[f.severity?.toLowerCase()] || 0; });
  riskScore = Math.min(riskScore, 100);

  const riskLabel = riskScore >= 75 ? 'Critical' :
                    riskScore >= 50 ? 'High' :
                    riskScore >= 25 ? 'Medium' :
                    riskScore >= 5 ? 'Low' : 'Secure';

  const enrichedFindings = findings.map(f => ({
    ...f,
    explanation: f.description,
    impact: f.danger,
    safeCodeExample: f.safeCode,
    references: getReferences(f.id)
  }));

  return {
    aiGenerated: false,
    report: {
      executiveSummary: findings.length > 0
        ? `The static analysis of the provided ${recon.language} code revealed ${findings.length} security vulnerabilities across ${[...new Set(findings.map(f => f.category))].length} categories. Immediate remediation is required for Critical and High severity findings before this code is deployed to production.`
        : `The static analysis of the provided ${recon.language} code found no obvious vulnerability patterns. However, a full dynamic analysis and manual code review is still recommended for production deployments.`,
      riskScore,
      riskLabel,
      totalFindings: findings.length,
      findings: enrichedFindings,
      prioritizedActions: getPrioritizedActions(findings),
      secureArchitectureRecommendations: [
        'Implement a dependency vulnerability scanner (e.g., npm audit, Snyk) in your CI/CD pipeline.',
        'Add a Web Application Firewall (WAF) in front of your API endpoints.',
        'Enable strict Content Security Policy (CSP) headers on all web responses.',
        'Use parameterized queries through an ORM (Sequelize, Prisma, SQLAlchemy) instead of raw SQL.',
        'Store all secrets in a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager).'
      ],
      complianceNotes: 'Hardcoded secrets and SQL injection violations may put you out of compliance with PCI-DSS Requirement 6 (Develop and Maintain Secure Systems), OWASP Top 10 A02 (Cryptographic Failures) and A03 (Injection). XSS issues relate to OWASP A03 and GDPR user data protection requirements.'
    }
  };
}

/** Payload shared by every AI provider. */
function payload(scanData) {
  return { recon: scanData.recon, findings: scanData.findings, summary: scanData.summary };
}

/**
 * Enrich via the Vercel serverless function (OpenAI). Returns the report or null.
 */
async function generateServerlessReport(scanData) {
  try {
    const res = await fetch(apiUrl('/api/report'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload(scanData))
    });
    if (res.ok) {
      const data = await res.json();
      if (data?.aiGenerated && data.report) return data.report;
    }
  } catch {
    // network error / function unavailable
  }
  return null;
}

/**
 * Enrich via a local Ollama model (fully offline). Calls Ollama's native chat
 * endpoint with JSON-formatted output. Returns the report or null on any failure.
 */
async function generateOllamaReport(scanData, cfg = getAiConfig()) {
  try {
    const res = await fetch(`${cfg.ollamaUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.ollamaModel,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildPrompt(payload(scanData)) }
        ],
        stream: false,
        format: 'json',
        options: { temperature: 0.2 }
      })
    });
    if (!res.ok) return null;
    const data = await res.json();
    const report = parseReportJson(data?.message?.content);
    return report || null;
  } catch {
    // Ollama not running / unreachable / CORS blocked
    return null;
  }
}

/**
 * Generate a report for scan results using the configured provider, with an
 * automatic fall-through to the static (no-LLM) report on any failure.
 * @returns {Promise<{ report, aiGenerated, provider }>}
 */
export async function generateReport(scanData, cfg = getAiConfig()) {
  const provider = cfg.provider || 'auto';

  if (provider === 'ollama') {
    const report = await generateOllamaReport(scanData, cfg);
    if (report) return { report, aiGenerated: true, provider: 'ollama' };
  } else if (provider === 'serverless') {
    const report = await generateServerlessReport(scanData);
    if (report) return { report, aiGenerated: true, provider: 'serverless' };
  } else if (provider === 'auto') {
    // Prefer the hosted function when a key is configured, else try local Ollama.
    const remote = await generateServerlessReport(scanData);
    if (remote) return { report: remote, aiGenerated: true, provider: 'serverless' };
    const local = await generateOllamaReport(scanData, cfg);
    if (local) return { report: local, aiGenerated: true, provider: 'ollama' };
  }
  // provider === 'static' or every attempt failed
  return { ...buildStaticReport(scanData), provider: 'static' };
}

/**
 * Quick probe: is AI enrichment available? Checks the provider the user picked
 * (serverless key present, or a reachable Ollama), so the UI badge is accurate.
 * @returns {Promise<{ enabled: boolean, provider: string }>}
 */
export async function checkAiEnabled(cfg = getAiConfig()) {
  const provider = cfg.provider || 'auto';

  const probeServerless = async () => {
    try {
      const res = await fetch(apiUrl('/api/report'), { method: 'GET' });
      if (!res.ok) return false;
      const data = await res.json();
      return !!data.aiEnabled;
    } catch {
      return false;
    }
  };
  const probeOllama = async () => {
    try {
      const res = await fetch(`${cfg.ollamaUrl}/api/tags`, { method: 'GET' });
      return res.ok;
    } catch {
      return false;
    }
  };

  if (provider === 'static') return { enabled: false, provider: 'static' };
  if (provider === 'ollama') return { enabled: await probeOllama(), provider: 'ollama' };
  if (provider === 'serverless') return { enabled: await probeServerless(), provider: 'serverless' };
  // auto
  if (await probeServerless()) return { enabled: true, provider: 'serverless' };
  if (await probeOllama()) return { enabled: true, provider: 'ollama' };
  return { enabled: false, provider: 'auto' };
}
