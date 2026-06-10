/**
 * Client-side vulnerability metadata helpers.
 * Maps each static rule to its OWASP Top 10 (2021) category and CWE id,
 * and provides ordering + report-export utilities used across the UI.
 */

// Severity ranking used for sorting and risk math (higher = worse).
export const SEVERITY_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1 };

// Map of rule id -> { owasp, cwe, cweUrl }. Falls back to category-based guess.
const RULE_META = {
  'SEC-SQLI':           { owasp: 'A03:2021 Injection',                 cwe: 'CWE-89'  },
  'SEC-XSS-DOM':        { owasp: 'A03:2021 Injection',                 cwe: 'CWE-79'  },
  'SEC-SECRET':         { owasp: 'A05:2021 Security Misconfiguration', cwe: 'CWE-798' },
  'SEC-WEAK-CRYPTO':    { owasp: 'A02:2021 Cryptographic Failures',    cwe: 'CWE-327' },
  'SEC-CMD-INJ':        { owasp: 'A03:2021 Injection',                 cwe: 'CWE-78'  },
  'SEC-JWT-UNSAFE':     { owasp: 'A07:2021 Auth Failures',             cwe: 'CWE-347' },
  'SEC-PATH-TRAVERSAL': { owasp: 'A01:2021 Broken Access Control',     cwe: 'CWE-22'  },
  'SEC-FILE-UPLOAD':    { owasp: 'A04:2021 Insecure Design',           cwe: 'CWE-434' },
};

const CATEGORY_FALLBACK = {
  'SQL Injection':                    { owasp: 'A03:2021 Injection',              cwe: 'CWE-89' },
  'XSS':                              { owasp: 'A03:2021 Injection',              cwe: 'CWE-79' },
  'Sensitive Data Exposure':         { owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-200' },
  'Weak Cryptography':               { owasp: 'A02:2021 Cryptographic Failures', cwe: 'CWE-327' },
  'Injection / Remote Code Execution': { owasp: 'A03:2021 Injection',            cwe: 'CWE-77' },
};

export function getVulnMeta(finding) {
  const meta = RULE_META[finding.id] || CATEGORY_FALLBACK[finding.category] || {
    owasp: 'OWASP Top 10', cwe: 'CWE',
  };
  const cweNum = (meta.cwe.match(/\d+/) || [])[0];
  return {
    ...meta,
    cweUrl: cweNum ? `https://cwe.mitre.org/data/definitions/${cweNum}.html` : 'https://cwe.mitre.org',
  };
}

/** Sort findings by the chosen key ('severity' | 'cvss' | 'file'). */
export function sortFindings(findings, key) {
  const copy = [...findings];
  if (key === 'cvss') {
    copy.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  } else if (key === 'file') {
    copy.sort((a, b) => String(a.file).localeCompare(String(b.file)) || a.line - b.line);
  } else {
    copy.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) || (b.cvss || 0) - (a.cvss || 0));
  }
  return copy;
}

/** Build a shareable Markdown report from a scan result object. */
export function buildMarkdownReport(results) {
  const { summary, findings = [], aiReport } = results;
  const lines = [];
  lines.push('# VulnShield Security Report');
  lines.push('');
  lines.push(`- **Generated:** ${new Date().toLocaleString()}`);
  lines.push(`- **Language:** ${summary?.language || 'Unknown'}`);
  lines.push(`- **Framework:** ${summary?.framework || 'None'}`);
  lines.push(`- **Total issues:** ${findings.length}`);
  if (aiReport?.riskScore != null) {
    lines.push(`- **Risk score:** ${aiReport.riskScore}/100 (${aiReport.riskLabel})`);
  }
  lines.push('');

  if (aiReport?.executiveSummary) {
    lines.push('## Executive Summary');
    lines.push('');
    lines.push(aiReport.executiveSummary);
    lines.push('');
  }

  if (findings.length === 0) {
    lines.push('No vulnerabilities were detected by the static rules engine. ✅');
    return lines.join('\n');
  }

  lines.push('## Findings');
  lines.push('');
  sortFindings(findings, 'severity').forEach((f, i) => {
    const meta = getVulnMeta(f);
    lines.push(`### ${i + 1}. ${f.title} — ${f.severity}`);
    lines.push('');
    lines.push(`- **Location:** \`${f.file}:${f.line}\``);
    lines.push(`- **CVSS:** ${f.cvss ?? 'N/A'} · **${meta.owasp}** · **${meta.cwe}**`);
    lines.push(`- **Description:** ${f.description}`);
    lines.push(`- **Risk:** ${f.danger}`);
    lines.push(`- **Fix:** ${f.fix}`);
    if (f.evidence) {
      lines.push('');
      lines.push('```');
      lines.push(`${f.line}: ${f.evidence}`);
      lines.push('```');
    }
    lines.push('');
  });

  return lines.join('\n');
}
