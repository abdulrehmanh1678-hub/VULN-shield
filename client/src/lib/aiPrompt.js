/**
 * Shared AI report prompt + schema.
 *
 * Used by every AI provider (local Ollama and the OpenAI serverless function)
 * so they all produce the same JSON report shape that AIReportViewer expects.
 */

export const SYSTEM_PROMPT = `You are VulnShield — an elite application security expert AI with deep expertise in OWASP Top 10,
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

Be precise, technical, and professional. Use real OWASP/CWE/CVE references where applicable.
Respond with ONLY the JSON object — no markdown fences, no commentary.`;

export function buildPrompt({ recon = {}, findings = [], summary = {} }) {
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

/**
 * Best-effort parse of an LLM JSON response. Local models occasionally wrap
 * output in markdown fences or add stray prose, so we strip fences and extract
 * the outermost {...} block before parsing.
 */
export function parseReportJson(text) {
  if (!text || typeof text !== 'string') return null;
  let s = text.trim();
  // Strip ```json ... ``` or ``` ... ``` fences if present.
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
  // Fall back to the first balanced-looking object slice.
  if (s[0] !== '{') {
    const start = s.indexOf('{');
    const end = s.lastIndexOf('}');
    if (start !== -1 && end > start) s = s.slice(start, end + 1);
  }
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
