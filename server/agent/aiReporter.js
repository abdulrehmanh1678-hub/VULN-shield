/**
 * AI Report Generator (Phase 5)
 * Uses OpenAI GPT or Google Gemini to transform raw scan findings into a
 * professional, enriched security audit report.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const OpenAI = require('openai');
const { getSystemPrompt, buildAnalysisPrompt } = require('./promptTemplates');

class AIReportGenerator {
  constructor() {
    this.openaiKey = process.env.OPENAI_API_KEY;
    this.geminiKey = process.env.GEMINI_API_KEY;
    this.provider = this._detectProvider();
    this.modelName = this.provider === 'openai'
      ? (process.env.OPENAI_MODEL || 'gpt-4o-mini')
      : 'gemini-1.5-flash';
  }

  _detectProvider() {
    if (this.openaiKey && this.openaiKey !== 'your_openai_api_key_here') return 'openai';
    if (this.geminiKey && this.geminiKey !== 'your_gemini_api_key_here') return 'gemini';
    return null;
  }

  isConfigured() {
    return !!this.provider;
  }

  getProviderLabel() {
    if (this.provider === 'openai') return 'OpenAI GPT';
    if (this.provider === 'gemini') return 'Gemini';
    return null;
  }

  async generateReport(scanData) {
    if (!this.isConfigured()) {
      console.warn('[AI] No API key configured. Returning enriched static report.');
      return this._generateStaticFallbackReport(scanData);
    }

    try {
      const prompt = buildAnalysisPrompt(scanData);
      let aiReport;

      if (this.provider === 'openai') {
        console.log(`[AI] Sending findings to OpenAI (${this.modelName}) for enrichment...`);
        aiReport = await this._generateWithOpenAI(prompt);
      } else {
        console.log('[AI] Sending findings to Gemini for enrichment...');
        aiReport = await this._generateWithGemini(prompt);
      }

      console.log('[AI] Report generation successful.');
      return { success: true, aiGenerated: true, report: aiReport };

    } catch (err) {
      console.error(`[AI] ${this.getProviderLabel()} API error:`, err.message);
      return this._generateStaticFallbackReport(scanData);
    }
  }

  async _generateWithOpenAI(prompt) {
    const openai = new OpenAI({ apiKey: this.openaiKey });
    const response = await openai.chat.completions.create({
      model: this.modelName,
      messages: [
        { role: 'system', content: getSystemPrompt() },
        { role: 'user', content: prompt }
      ],
      response_format: { type: 'json_object' }
    });

    const responseText = response.choices[0]?.message?.content;
    if (!responseText) throw new Error('Empty response from OpenAI');
    return JSON.parse(responseText);
  }

  async _generateWithGemini(prompt) {
    const genAI = new GoogleGenerativeAI(this.geminiKey);
    const model = genAI.getGenerativeModel({
      model: this.modelName,
      systemInstruction: getSystemPrompt()
    });

    const result = await model.generateContent(prompt);
    const responseText = result.response.text();

    const jsonMatch = responseText.match(/```json\s*([\s\S]*?)\s*```/) ||
                      responseText.match(/```\s*([\s\S]*?)\s*```/) ||
                      [null, responseText];

    const jsonText = jsonMatch[1] || responseText;
    return JSON.parse(jsonText);
  }

  _generateStaticFallbackReport(scanData) {
    const { findings, summary, recon } = scanData;

    const severityWeights = { critical: 40, high: 20, medium: 10, low: 5 };
    let riskScore = 0;
    findings.forEach(f => {
      riskScore += severityWeights[f.severity?.toLowerCase()] || 0;
    });
    riskScore = Math.min(riskScore, 100);

    const riskLabel = riskScore >= 75 ? 'Critical' :
                      riskScore >= 50 ? 'High' :
                      riskScore >= 25 ? 'Medium' :
                      riskScore >= 5  ? 'Low' : 'Secure';

    const enrichedFindings = findings.map(f => ({
      ...f,
      explanation: f.description,
      impact: f.danger,
      safeCodeExample: f.safeCode,
      references: this._getReferences(f.id)
    }));

    const prioritizedActions = this._getPrioritizedActions(findings);

    return {
      success: true,
      aiGenerated: false,
      report: {
        executiveSummary: findings.length > 0 
          ? `The static analysis of the provided ${recon.language} code revealed ${findings.length} security vulnerabilities across ${[...new Set(findings.map(f => f.category))].length} categories. Immediate remediation is required for Critical and High severity findings before this code is deployed to production.`
          : `The static analysis of the provided ${recon.language} code found no obvious vulnerability patterns. However, a full dynamic analysis and manual code review is still recommended for production deployments.`,
        riskScore,
        riskLabel,
        totalFindings: findings.length,
        findings: enrichedFindings,
        prioritizedActions,
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

  _getReferences(ruleId) {
    const refs = {
      'SEC-SQLI': ['OWASP A03:2021 – Injection', 'CWE-89: SQL Injection', 'https://owasp.org/www-community/attacks/SQL_Injection'],
      'SEC-XSS-DOM': ['OWASP A03:2021 – Injection (XSS)', 'CWE-79: Cross-site Scripting', 'https://owasp.org/www-community/attacks/xss/'],
      'SEC-SECRET': ['OWASP A02:2021 – Cryptographic Failures', 'CWE-312: Cleartext Storage of Sensitive Information'],
      'SEC-WEAK-CRYPTO': ['OWASP A02:2021 – Cryptographic Failures', 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm'],
      'SEC-CMD-INJ': ['OWASP A03:2021 – Injection (Command)', 'CWE-78: OS Command Injection'],
      'SEC-JWT-UNSAFE': ['OWASP A07:2021 – Identification and Authentication Failures', 'CWE-347: Improper Verification of Cryptographic Signature'],
      'SEC-PATH-TRAVERSAL': ['OWASP A01:2021 – Broken Access Control', 'CWE-22: Path Traversal'],
      'SEC-FILE-UPLOAD': ['OWASP A04:2021 – Insecure Design', 'CWE-434: Unrestricted Upload of File with Dangerous Type']
    };
    const ruleBase = ruleId.replace(/-\d+$/, '');
    return refs[ruleBase] || ['OWASP Top 10 2021', 'CWE Reference Available'];
  }

  _getPrioritizedActions(findings) {
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
}

module.exports = new AIReportGenerator();
