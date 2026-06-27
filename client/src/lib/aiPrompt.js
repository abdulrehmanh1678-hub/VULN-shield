/**
 * Shared AI report prompt + schema.
 *
 * ARCHITECTURE NOTE (verified-findings pattern):
 * The static rules engine is the ONLY source of truth for what counts as a
 * vulnerability. The AI is never asked to "find" anything — it receives the
 * exact, final list of confirmed findings (ids, severities, CVSS, lines) and
 * its job is strictly limited to explaining, prioritizing, and recommending
 * fixes for THOSE findings. It cannot add, remove, or re-score a finding.
 * report.js additionally runs verifyReport() after parsing to mechanically
 * enforce this — the prompt below is the first line of defense, not the only one.
 */

export const SYSTEM_PROMPT = `You are VulnShield's remediation-explanation assistant.

You are NOT a vulnerability scanner. A separate, deterministic static-analysis engine has
ALREADY scanned the code and produced a final, confirmed list of findings. That list is the
only ground truth. Your job is strictly limited to:
1. Explaining each CONFIRMED finding's real-world impact and attack scenario
2. Writing a fix and a safe code example for each CONFIRMED finding
3. Adding OWASP/CWE references for each CONFIRMED finding
4. Writing an executive summary and prioritized action list based ONLY on the CONFIRMED findings

STRICT RULES — violating any of these makes your output invalid and it will be rejected:
- You MUST NOT invent, add, or report any vulnerability that is not in the CONFIRMED FINDINGS list given to you.
- You MUST NOT change the "id", "severity", "cvss", "file", or "line" of any finding. Echo them back exactly as given.
- You MUST return exactly the same number of findings you were given — no more, no fewer.
- If the CONFIRMED FINDINGS list is empty, "findings" in your output MUST be an empty array. Do not invent issues to fill it.
- You have NOT seen the raw source code, only the confirmed findings metadata below. Do not refer to or assume any code beyond what's provided in each finding's "evidence" field.

Always respond with a valid JSON object following this exact schema:
{
  "executiveSummary": "string — 2-3 sentence high-level security health overview",
  "riskScore": number (0-100, where 100 is the most dangerous),
  "riskLabel": "Critical | High | Medium | Low | Secure",
  "totalFindings": number,
  "findings": [
    {
      "id": "string (MUST exactly match an input finding id)",
      "title": "string", "category": "string",
      "severity": "Critical | High | Medium | Low (MUST exactly match input)",
      "cvss": number (MUST exactly match input),
      "file": "string (MUST exactly match input)", "line": number (MUST exactly match input),
      "evidence": "string (MUST exactly match input)",
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

  return `Below is the CONFIRMED FINDINGS list produced by the deterministic static-analysis engine.
This is ground truth. Do not add to it, remove from it, or alter any id/severity/cvss/file/line value.

=== SCAN METADATA ===
Detected Language: ${recon.language}
Detected Framework: ${recon.framework}
Entry Points Found: ${recon.entryPoints ? recon.entryPoints.length : 0}
Total Vulnerabilities: ${summary.totalVulnerabilities}
Scan Timestamp: ${summary.timestamp}

=== CONFIRMED FINDINGS (${findings.length} total — ground truth, do not modify count or identity) ===
${findings.length > 0 ? findingsSummary : 'EMPTY — no vulnerabilities were confirmed by the static rules engine. Your "findings" array MUST be empty. Do not invent any.'}

=== YOUR TASK ===
1. For each confirmed finding above, write a detailed technical explanation, a realistic attack
   scenario, business impact, a concrete fix, and a safe code example. Echo back id/severity/cvss/file/line exactly.
2. Add relevant OWASP Top 10, CWE, or CVE references for each finding.
3. Write an executive summary and an overall risk score (0-100) based only on these findings.
4. Provide a prioritized list of the top 5 immediate actions.
5. Return valid JSON following the schema in your system prompt. Do not add findings beyond the ${findings.length} given.`;
}

/**
 * Best-effort parse of an LLM JSON response. Local models occasionally wrap
 * output in markdown fences or add stray prose, so we strip fences and extract
 * the outermost {...} block before parsing.
 */
export function parseReportJson(text) {
  if (!text || typeof text !== 'string') return null;
  let s = text.trim();
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) s = fence[1].trim();
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

/**
 * Mechanical verification that the AI didn't violate the ground-truth rules.
 * This is the actual enforcement — the prompt above is just the first line of
 * defense, this function is what makes the claim true rather than hoped-for.
 *
 * @param {object} aiReport - parsed JSON from the AI
 * @param {Array} confirmedFindings - the original findings array sent to the AI
 * @returns {{ valid: boolean, report: object, issues: string[] }}
 *   - report has any invalid findings stripped and verified:true/false stamped on each
 */
export function verifyReport(aiReport, confirmedFindings) {
  const issues = [];
  if (!aiReport || !Array.isArray(aiReport.findings)) {
    return { valid: false, report: aiReport, issues: ['AI response missing findings array'] };
  }

  const confirmedById = new Map(confirmedFindings.map(f => [String(f.id), f]));
  const seenIds = new Set();
  const cleanFindings = [];

  for (const aiFinding of aiReport.findings) {
    const ground = confirmedById.get(String(aiFinding.id));
    if (!ground) {
      issues.push(`Rejected hallucinated finding not in confirmed list: ${aiFinding.id || '(no id)'}`);
      continue; // drop it — never shown to the user
    }
    if (seenIds.has(ground.id)) {
      issues.push(`Rejected duplicate finding: ${ground.id}`);
      continue;
    }
    seenIds.add(ground.id);

    // Force the immutable fields back to ground truth, regardless of what the AI wrote.
    cleanFindings.push({
      ...aiFinding,
      id: ground.id,
      severity: ground.severity,
      cvss: ground.cvss,
      file: ground.file,
      line: ground.line,
      evidence: ground.evidence,
      verified: true
    });
  }

  // Flag any confirmed finding the AI silently dropped (it must explain all of them).
  for (const f of confirmedFindings) {
    if (!seenIds.has(f.id)) {
      issues.push(`AI omitted a confirmed finding, re-inserting with static text: ${f.id}`);
      cleanFindings.push({
        ...f,
        explanation: f.description || 'Confirmed by static analysis.',
        impact: f.danger || 'See severity rating.',
        fix: f.fix || 'Review and remediate per standard guidance for this vulnerability class.',
        safeCodeExample: f.safeCode || '',
        references: [],
        verified: true
      });
    }
  }

  return {
    valid: issues.length === 0,
    report: { ...aiReport, findings: cleanFindings, totalFindings: cleanFindings.length },
    issues
  };
}
