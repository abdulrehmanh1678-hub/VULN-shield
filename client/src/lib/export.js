/**
 * Client-side report export (no server).
 * JSON  → Blob download.
 * PDF   → opens a formatted, print-ready report window; the browser's
 *         "Save as PDF" produces the file. Works on any static host.
 */

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function exportJSON(results) {
  const payload = {
    scanId: results.scanId,
    generatedAt: new Date().toISOString(),
    summary: results.summary,
    recon: results.recon,
    findings: results.findings,
    aiReport: results.aiReport,
    aiGenerated: results.aiGenerated
  };
  download(`vulnshield-report-${results.scanId?.slice(0, 8) || 'scan'}.json`, JSON.stringify(payload, null, 2), 'application/json');
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function exportPDF(results) {
  const report = results.aiReport || {};
  const findings = report.findings || results.findings || [];
  const severityColor = { Critical: '#dc2626', High: '#ea580c', Medium: '#d97706', Low: '#65a30d' };

  const findingsHtml = findings.map((f, i) => `
    <div class="finding">
      <h3>${i + 1}. ${esc(f.title)}
        <span class="sev" style="background:${severityColor[f.severity] || '#64748b'}">${esc(f.severity)}${f.cvss ? ` · CVSS ${esc(f.cvss)}` : ''}</span>
      </h3>
      <p class="meta">${esc(f.category)} — ${esc(f.file)}:${esc(f.line)}</p>
      <pre>${esc(f.evidence)}</pre>
      <p><strong>Why it matters:</strong> ${esc(f.explanation || f.description || '')}</p>
      ${f.impact ? `<p><strong>Impact:</strong> ${esc(f.impact)}</p>` : ''}
      <p><strong>Fix:</strong> ${esc(f.fix || '')}</p>
      ${(f.references || []).length ? `<p class="refs"><strong>References:</strong> ${(f.references || []).map(esc).join(' · ')}</p>` : ''}
    </div>`).join('');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>VulnShield Report</title>
  <style>
    body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a;max-width:820px;margin:32px auto;padding:0 24px;line-height:1.5}
    h1{font-size:24px;margin-bottom:4px}.sub{color:#64748b;font-size:13px;margin-top:0}
    .score{display:inline-block;padding:8px 16px;border-radius:10px;background:#0f172a;color:#fff;font-weight:700;margin:12px 0}
    .finding{border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin:14px 0;page-break-inside:avoid}
    .finding h3{font-size:15px;margin:0 0 4px;display:flex;justify-content:space-between;align-items:center;gap:8px}
    .sev{color:#fff;font-size:11px;padding:2px 8px;border-radius:6px;font-weight:600;white-space:nowrap}
    .meta{color:#64748b;font-size:12px;margin:2px 0 8px}
    pre{background:#f1f5f9;padding:10px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
    .refs{font-size:11px;color:#475569}p{font-size:13px;margin:6px 0}
    ul{font-size:13px}h2{font-size:17px;margin-top:28px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}
    @media print{body{margin:0}}
  </style></head><body>
    <h1>🛡 VulnShield Security Report</h1>
    <p class="sub">Generated ${new Date().toLocaleString()} · ${esc(results.recon?.language || 'unknown')} · ${findings.length} finding(s) · ${results.aiGenerated ? 'AI-enriched' : 'Static analysis'}</p>
    <span class="score">Risk: ${esc(report.riskLabel || 'N/A')}${report.riskScore != null ? ` (${esc(report.riskScore)}/100)` : ''}</span>
    ${report.executiveSummary ? `<h2>Executive Summary</h2><p>${esc(report.executiveSummary)}</p>` : ''}
    ${(report.prioritizedActions || []).length ? `<h2>Prioritized Actions</h2><ul>${report.prioritizedActions.map(a => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
    <h2>Findings</h2>
    ${findings.length ? findingsHtml : '<p>No vulnerabilities detected.</p>'}
    ${report.complianceNotes ? `<h2>Compliance Notes</h2><p>${esc(report.complianceNotes)}</p>` : ''}
    <script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>
  </body></html>`;

  const w = window.open('', '_blank');
  if (!w) return;
  w.document.write(html);
  w.document.close();
}
