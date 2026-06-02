/**
 * PDF Report Generator (Phase 8)
 * Generates a professional-quality PDF security audit report from scan results
 * using the pdfkit library.
 */

const PDFDocument = require('pdfkit');

const SEVERITY_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Secure: '#10b981'
};

/**
 * Generate a PDF buffer from scan and AI report data.
 * @param {object} scanData - Raw orchestrator scan output
 * @param {object} aiReportData - AI-generated report object
 * @returns {Promise<Buffer>} - PDF file as buffer
 */
function generatePDF(scanData, aiReportData) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50, size: 'A4' });
      const buffers = [];
      doc.on('data', chunk => buffers.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(buffers)));
      doc.on('error', reject);

      const report = aiReportData?.report || {};
      const summary = scanData?.summary || {};
      const findings = report.findings || scanData?.findings || [];

      // === COVER PAGE ===
      doc.rect(0, 0, doc.page.width, 160).fill('#0b0d12');
      doc.fill('#ffffff').fontSize(28).font('Helvetica-Bold')
         .text('VULNSHIELD', 50, 55, { align: 'left' });
      doc.fill('#6366f1').fontSize(14)
         .text('AI-Powered Security Audit Report', 50, 90);
      doc.fill('#9ca3af').fontSize(10)
         .text(`Generated: ${new Date().toUTCString()}`, 50, 115)
         .text(`Language: ${summary.language || 'N/A'}  |  Framework: ${summary.framework || 'N/A'}`, 50, 130);
      
      doc.moveDown(6);

      // === EXECUTIVE SUMMARY ===
      _sectionHeader(doc, 'Executive Summary');
      doc.fill('#1f2937').rect(50, doc.y, doc.page.width - 100, 1).fill();
      doc.moveDown(0.5);
      
      const riskColor = SEVERITY_COLORS[report.riskLabel] || '#6366f1';
      doc.fill('#111827').roundedRect(50, doc.y, doc.page.width - 100, 70, 8).fill();
      doc.fill(riskColor).fontSize(36).font('Helvetica-Bold')
         .text(String(report.riskScore ?? 'N/A'), 65, doc.y - 60);
      doc.fill('#ffffff').fontSize(12)
         .text(`Risk Score / 100`, 65, doc.y - 22);
      doc.fill(riskColor).fontSize(18).font('Helvetica-Bold')
         .text(report.riskLabel || 'N/A', 160, doc.y - 52);
      doc.fill('#d1d5db').fontSize(10).font('Helvetica')
         .text(`${findings.length} vulnerabilities found across ${summary.language} code`, 160, doc.y - 28);
      
      doc.moveDown(5);
      doc.fill('#374151').fontSize(10).font('Helvetica')
         .text(report.executiveSummary || 'No executive summary available.', 50, doc.y, { width: doc.page.width - 100 });
      doc.moveDown(2);

      // === FINDINGS ===
      _sectionHeader(doc, 'Vulnerability Findings');
      doc.fill('#1f2937').rect(50, doc.y, doc.page.width - 100, 1).fill();
      doc.moveDown(0.5);

      if (findings.length === 0) {
        doc.fill('#10b981').fontSize(12).text('✓ No vulnerabilities detected.', 50, doc.y);
      } else {
        findings.forEach((finding, idx) => {
          if (doc.y > 700) doc.addPage();

          const sevColor = SEVERITY_COLORS[finding.severity] || '#6b7280';
          
          // Finding card header
          doc.fill('#111827').roundedRect(50, doc.y, doc.page.width - 100, 28, 4).fill();
          doc.fill(sevColor).fontSize(9).font('Helvetica-Bold')
             .text(`[${finding.severity?.toUpperCase() || 'UNKNOWN'}]  CVSS ${finding.cvss || 'N/A'}`, 60, doc.y - 20);
          doc.fill('#ffffff').fontSize(11).font('Helvetica-Bold')
             .text(`${idx + 1}. ${finding.title}`, 160, doc.y - 32);
          
          doc.moveDown(0.3);
          doc.fill('#6b7280').fontSize(9).font('Helvetica')
             .text(`File: ${finding.file}  |  Line: ${finding.line || 'N/A'}  |  Category: ${finding.category}`, 55, doc.y);
          doc.moveDown(0.6);

          if (finding.explanation || finding.description) {
            doc.fill('#374151').fontSize(9).font('Helvetica-Bold').text('Explanation:', 55, doc.y);
            doc.fill('#4b5563').fontSize(9).font('Helvetica')
               .text(finding.explanation || finding.description, 55, doc.y, { width: doc.page.width - 110 });
            doc.moveDown(0.5);
          }

          if (finding.impact || finding.danger) {
            doc.fill('#b91c1c').fontSize(9).font('Helvetica-Bold').text('Impact:', 55, doc.y);
            doc.fill('#4b5563').fontSize(9).font('Helvetica')
               .text(finding.impact || finding.danger, 55, doc.y, { width: doc.page.width - 110 });
            doc.moveDown(0.5);
          }

          if (finding.fix) {
            doc.fill('#065f46').fontSize(9).font('Helvetica-Bold').text('Recommended Fix:', 55, doc.y);
            doc.fill('#4b5563').fontSize(9).font('Helvetica')
               .text(finding.fix, 55, doc.y, { width: doc.page.width - 110 });
            doc.moveDown(0.5);
          }

          if (finding.evidence) {
            doc.fill('#111827').rect(55, doc.y, doc.page.width - 110, 20).fill();
            doc.fill('#f87171').fontSize(8).font('Courier')
               .text(`${finding.line}: ${finding.evidence}`, 60, doc.y - 14, { width: doc.page.width - 120 });
            doc.moveDown(0.5);
          }

          doc.moveDown(1.5);
        });
      }

      // === PRIORITIZED ACTIONS ===
      if (report.prioritizedActions?.length > 0) {
        if (doc.y > 600) doc.addPage();
        _sectionHeader(doc, 'Prioritized Remediation Actions');
        doc.fill('#1f2937').rect(50, doc.y, doc.page.width - 100, 1).fill();
        doc.moveDown(0.5);
        report.prioritizedActions.forEach((action, i) => {
          doc.fill('#374151').fontSize(10).font('Helvetica')
             .text(`${i + 1}. ${action}`, 50, doc.y, { width: doc.page.width - 100 });
          doc.moveDown(0.5);
        });
      }

      // === FOOTER ===
      doc.addPage();
      doc.fill('#9ca3af').fontSize(9).font('Helvetica')
         .text('Generated by VulnShield — AI-Powered Security Analysis Platform', 50, 760, { align: 'center', width: doc.page.width - 100 });

      doc.end();

    } catch (err) {
      reject(err);
    }
  });
}

function _sectionHeader(doc, title) {
  doc.fill('#6366f1').fontSize(14).font('Helvetica-Bold').text(title, 50, doc.y);
  doc.moveDown(0.5);
}

module.exports = { generatePDF };
