/**
 * AI Prompt Templates (Phase 5)
 * Defines the system prompt and user prompt templates used to generate
 * professional security reports from structured scan findings.
 */

/**
 * Build the AI system instructions prompt.
 * @returns {string}
 */
function getSystemPrompt() {
  return `You are VulnShield — an elite application security expert AI with deep expertise in OWASP Top 10, 
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
      "id": "string",
      "title": "string",
      "category": "string",
      "severity": "Critical | High | Medium | Low",
      "cvss": number (0.0 - 10.0),
      "file": "string",
      "line": number,
      "evidence": "string — the actual vulnerable code line",
      "explanation": "string — detailed technical explanation of why this is a vulnerability",
      "impact": "string — what an attacker can realistically do with this vulnerability",
      "fix": "string — step-by-step actionable remediation advice",
      "safeCodeExample": "string — a corrected code snippet demonstrating the secure implementation",
      "references": ["string — OWASP/CWE/CVE references relevant to this vulnerability"]
    }
  ],
  "prioritizedActions": ["string — ordered list of top 5 immediate security actions"],
  "secureArchitectureRecommendations": ["string — broader architectural security improvements"],
  "complianceNotes": "string — notes on how the findings relate to standards like OWASP, PCI-DSS, SOC2"
}

Be precise, technical, and professional. Use real OWASP/CWE/CVE references where applicable.`;
}

/**
 * Build the user-facing prompt from scan results.
 * @param {object} scanData - The structured output from the orchestrator
 * @returns {string}
 */
function buildAnalysisPrompt(scanData) {
  const { recon, findings, summary } = scanData;

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

module.exports = { getSystemPrompt, buildAnalysisPrompt };
