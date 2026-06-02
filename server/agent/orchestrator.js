/**
 * Agent Orchestrator (Phase 3)
 * Coordinates the agentic scan execution pipeline:
 * 1. Recon (Detect Language, Framework, entry points, suspicious patterns)
 * 2. Routing/Decision (Decide which modules to execute)
 * 3. Modular Scan Execution (Run selected scanner rules/modules)
 * 4. Aggregation (Combine and structure findings)
 */

const { scanCode, runRecon, VULNERABILITY_RULES } = require('./tools');

class ScanAgentOrchestrator {
  constructor() {
    this.logs = [];
  }

  log(step, message, data = null) {
    const timestamp = new Date().toISOString();
    this.logs.push({ timestamp, step, message, data });
    console.log(`[Agent Orchestrator] [${step}] ${message}`);
  }

  async runScan(code, filename = 'pasted_code.js') {
    this.logs = []; // reset
    this.log('INIT', `Starting analysis on file: ${filename}`);

    // --- STEP 1: RECON ---
    this.log('RECON_START', 'Scanning code file for language, framework, and patterns...');
    const recon = runRecon(code);
    
    // Identify entry points (e.g., API endpoints, route handlers)
    const entryPoints = [];
    const lines = code.split(/\r?\n/);
    lines.forEach((line, idx) => {
      if (/(?:app|router)\.(?:get|post|put|delete|use|patch)\s*\(/.test(line)) {
        entryPoints.push({ line: idx + 1, detail: line.trim() });
      } else if (/def\s+[a-zA-Z0-9_]+\s*\(.*req.*res.*\)/.test(line) || /def\s+[a-zA-Z0-9_]+\s*\(.*request.*\)/.test(line)) {
        entryPoints.push({ line: idx + 1, detail: line.trim() });
      }
    });

    recon.entryPoints = entryPoints;
    this.log('RECON_COMPLETE', `Recon results: Language=${recon.language}, Framework=${recon.framework}, EntryPoints=${entryPoints.length}`, recon);

    // --- STEP 2: SCAN ROUTING DECISION ---
    this.log('ROUTING', 'Determining active scanner modules based on Recon metadata...');
    
    const activeModules = [];
    
    // Hardcoded secrets and weak crypto are language-agnostic rule checks
    activeModules.push('SEC-SECRET');
    activeModules.push('SEC-WEAK-CRYPTO');
    this.log('ROUTING_DECISION', 'Enabling global modules: Sensitive Data (Secrets) & Weak Cryptography');

    // Language-specific routing
    if (recon.language === 'JavaScript/TypeScript') {
      activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD');
      this.log('ROUTING_DECISION', 'Detected JS environment: Enabling SQLi, XSS, Cmd Injection, JWT Auth, Path Traversal, and Insecure Upload modules');
    } else if (recon.language === 'Python') {
      activeModules.push('SEC-SQLI', 'SEC-CMD-INJ', 'SEC-PATH-TRAVERSAL');
      this.log('ROUTING_DECISION', 'Detected Python environment: Enabling SQLi, Cmd Injection, and Path Traversal modules');
    } else {
      // Default fallback: enable all scans
      activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD');
      this.log('ROUTING_DECISION', 'Fallback: Enabling all scanner modules for general static parsing');
    }

    // --- STEP 3: SCANNER EXECUTION ---
    this.log('EXECUTION_START', `Executing ${activeModules.length} selected scanner modules...`);
    const allFindings = [];

    // Filter rule definitions by selected modules
    const selectedRules = VULNERABILITY_RULES.filter(rule => activeModules.includes(rule.id));

    // Run each module sequentially (simulating isolated tools execution)
    for (const rule of selectedRules) {
      this.log('MODULE_RUN', `Running scanner module: ${rule.title} (${rule.id})`);
      
      // Execute the scanner rule against the code
      const findingsForModule = [];
      lines.forEach((lineContent, i) => {
        if (rule.pattern.test(lineContent)) {
          findingsForModule.push({
            id: `${rule.id}-${i + 1}`,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            cvss: rule.cvss,
            file: filename,
            line: i + 1,
            evidence: lineContent.trim(),
            description: rule.description,
            danger: rule.danger,
            fix: rule.fix,
            safeCode: rule.safeCode
          });
        }
      });

      if (findingsForModule.length > 0) {
        this.log('MODULE_RESULT', `Module ${rule.id} found ${findingsForModule.length} vulnerability instance(s)`, findingsForModule);
        allFindings.push(...findingsForModule);
      } else {
        this.log('MODULE_RESULT', `Module ${rule.id} completed. No vulnerabilities found.`);
      }
    }

    // --- STEP 4: AGGREGATION & REPORTING ---
    this.log('AGGREGATION', `Combining results. Total vulnerabilities found: ${allFindings.length}`);
    
    const results = {
      success: true,
      summary: {
        totalVulnerabilities: allFindings.length,
        language: recon.language,
        framework: recon.framework,
        entryPointsCount: entryPoints.length,
        timestamp: new Date().toISOString()
      },
      recon: recon,
      findings: allFindings,
      agentLogs: this.logs
    };

    this.log('AGENT_COMPLETE', 'Agent run finished. Generating payload.');
    return results;
  }
}

module.exports = new ScanAgentOrchestrator();
