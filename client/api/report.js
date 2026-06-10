/**
 * Vercel Serverless Function — AI security report generator.
 *
 * GET  /api/report   → { aiEnabled: boolean }   (probe for the UI badge)
 * POST /api/report   → { aiGenerated: true, report }   on success
 *
 * Keeps the OpenAI key server-side (set OPENAI_API_KEY in the Vercel project's
 * Environment Variables). If no key is configured or the call fails, responds
 * so the browser falls back to its built-in static report.
 */

const SYSTEM_PROMPT = `You are VulnShield — an elite application security expert AI with deep expertise in OWASP Top 10,
CVE databases, CVSS scoring, secure coding practices, and penetration testing methodologies.

Your role is to analyze structured security scan results from a static code analysis tool and produce
a comprehensive, professional-grade security audit report.

Always respond with a valid JSON object following this exact schema:
{
  "executiveSummary": "string — 2-3 sentence high-level security health overview",
  "riskScore": number (0-100, where 100 is the most dangerous),
  "riskLabel": "Critical | High | Medium | Low | Secure",
  "totalFindings": number,
  "findings": [
    {
      "id": "string", "title": "string", "category": "string",
      "severity": "Critical | High | Medium | Low", "cvss": number,
      "file": "string", "line": number, "evidence": "string",
      "explanation": "string", "impact": "string", "fix": "string",
      "safeCodeExample": "string", "references": ["string"]
    }
  ],
  "prioritizedActions": ["string"],
  "secureArchitectureRecommendations": ["string"],
  "complianceNotes": "string"
}

Be precise, technical, and professional. Use real OWASP/CWE/CVE references where applicable.`;

function buildPrompt({ recon = {}, findings = [], summary = {} }) {
  const findingsSummary = findings.map((f, i) =>
    `[${i + 1}] Rule ID: ${f.id}
     Title: ${f.title}
     Category: ${f.category}
     Severity: ${f.severity} (CVSS ${f.cvss})
     File: ${f.file} | Line: ${f.line}
     Evidence: ${f.evidence}
     Initial Analysis: ${f.description}`
  ).join('\n\n');

  return `Please analyze the following static code analysis results and generate a professional security audit report.

=== SCAN METADATA ===
Detected Language: ${recon.language}
Detected Framework: ${recon.framework}
Entry Points Found: ${recon.entryPoints ? recon.entryPoints.length : 0}
Total Vulnerabilities: ${summary.totalVulnerabilities}
Scan Timestamp: ${summary.timestamp}

=== DETECTED VULNERABILITIES ===
${findings.length > 0 ? findingsSummary : 'No vulnerabilities were detected by the static rules engine.'}

=== INSTRUCTIONS ===
1. Evaluate each finding above with deep security expertise
2. Enrich each finding with detailed technical explanations, realistic attack scenarios, and fix guidance
3. Add relevant OWASP Top 10, CWE, or CVE references for each finding
4. Generate an executive summary with an overall risk score (0-100)
5. Provide a prioritized list of the top 5 immediate actions the developer should take
6. Return your response as valid JSON following the schema defined in your system prompt`;
}

function getKey() {
  const key = process.env.OPENAI_API_KEY;
  if (!key || key === 'your_openai_api_key_here') return null;
  return key;
}

export default async function handler(req, res) {
  const apiKey = getKey();

  if (req.method === 'GET') {
    return res.status(200).json({ aiEnabled: !!apiKey, provider: apiKey ? 'OpenAI GPT' : null });
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!apiKey) {
    // No key configured → signal the client to use its static fallback.
    return res.status(200).json({ aiGenerated: false });
  }

  try {
    const scanData = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';

    const apiRes = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildPrompt(scanData) }
        ],
        response_format: { type: 'json_object' }
      })
    });

    if (!apiRes.ok) {
      const detail = await apiRes.text();
      console.error('[report] OpenAI error', apiRes.status, detail);
      return res.status(200).json({ aiGenerated: false });
    }

    const data = await apiRes.json();
    const text = data.choices?.[0]?.message?.content;
    if (!text) return res.status(200).json({ aiGenerated: false });

    return res.status(200).json({ aiGenerated: true, report: JSON.parse(text) });
  } catch (err) {
    console.error('[report] failure', err);
    return res.status(200).json({ aiGenerated: false });
  }
}
