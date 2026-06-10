/**
 * Browser-side Static Rules Engine + Agent Orchestrator
 * Ported from the original Express backend (server/agent/tools.js + orchestrator.js)
 * so the scan runs entirely in the browser — no server required.
 */

export const VULNERABILITY_RULES = [
  {
    id: 'SEC-SQLI',
    title: 'Potential SQL Injection',
    category: 'SQL Injection',
    severity: 'High',
    cvss: 8.2,
    description: 'Raw SQL query string concatenation detected. Using string interpolation or concatenation in queries can allow attackers to inject malicious database statements.',
    danger: 'Allows unauthorized database read, write, modification, or total administrative takeover (e.g., dropping tables, data theft).',
    fix: 'Use parameterized queries or prepared statements instead of dynamic SQL string assembly.',
    safeCode: '// Vulnerable:\n// db.query("SELECT * FROM users WHERE name = \'" + input + "\'");\n\n// Secure:\ndb.query("SELECT * FROM users WHERE name = ?", [input]);',
    pattern: /(?:select|insert|update|delete|where|join|from).*(?:\+.*\$\{|\$\{|concat.*\(|\+.*[a-zA-Z_])/i
  },
  {
    id: 'SEC-XSS-DOM',
    title: 'Potential DOM-based Cross-Site Scripting (XSS)',
    category: 'XSS',
    severity: 'Medium',
    cvss: 6.1,
    description: 'Direct insertion of untrusted user input into DOM properties (like innerHTML or dangerouslySetInnerHTML) without sanitization.',
    danger: 'Allows arbitrary JavaScript execution in the user\'s browser context, leading to session hijacking, defacement, or credential theft.',
    fix: 'Sanitize HTML inputs using DOMPurify before setting, or use safe properties like textContent / innerText.',
    safeCode: '// Vulnerable:\n// element.innerHTML = userInput;\n\n// Secure:\nimport DOMPurify from \'dompurify\';\nelement.innerHTML = DOMPurify.sanitize(userInput);\n// OR:\nelement.textContent = userInput;',
    pattern: /(?:innerHTML\s*=|\.dangerouslySetInnerHTML\s*=)/i
  },
  {
    id: 'SEC-SECRET',
    title: 'Hardcoded Secret or API Key',
    category: 'Sensitive Data Exposure',
    severity: 'Critical',
    cvss: 9.8,
    description: 'Potential API key, password, private key, or client secret hardcoded directly in the source code.',
    danger: 'If the repository is leaked or accessed by unauthorized users, credentials can be used to hijack resources, databases, or cloud accounts.',
    fix: 'Store secrets in environment variables (.env) or use a secure secrets manager (AWS Secrets Manager, HashiCorp Vault).',
    safeCode: '// Vulnerable:\n// const API_KEY = "AIzaSyD-example-key";\n\n// Secure:\nconst API_KEY = process.env.GEMINI_API_KEY;',
    pattern: /(?:const|let|var|define)?.*(?:api_key|apikey|secret|password|passwd|private_key|token|access_key|jwt_secret)\s*=\s*['"`][a-zA-Z0-9_\-\/+=]{10,}['"`]/i
  },
  {
    id: 'SEC-WEAK-CRYPTO',
    title: 'Weak Cryptographic Algorithm',
    category: 'Weak Cryptography',
    severity: 'Medium',
    cvss: 5.9,
    description: 'Use of deprecated or cryptographically broken hashing algorithms (like MD5 or SHA-1).',
    danger: 'Collision attacks and rapid pre-image lookups allow attackers to crack hashes (e.g., user passwords) within seconds.',
    fix: 'Upgrade hashing to modern, secure algorithms like bcrypt, argon2, or SHA-256/SHA-512.',
    safeCode: '// Vulnerable:\n// crypto.createHash(\'md5\').update(password).digest(\'hex\');\n\n// Secure:\n// const bcrypt = require(\'bcrypt\');\n// await bcrypt.hash(password, 10);',
    pattern: /(?:createHash\s*\(\s*['"`](?:md5|sha1)['"`]\)|md5\s*\(|sha1\s*\()/i
  },
  {
    id: 'SEC-CMD-INJ',
    title: 'Potential Command Injection',
    category: 'Injection / Remote Code Execution',
    severity: 'Critical',
    cvss: 9.8,
    description: 'Executing system commands with dynamic variables/arguments built from user inputs without strict sanitization.',
    danger: 'Enables remote code execution (RCE), allowing an attacker to run arbitrary shell commands on the host server.',
    fix: 'Avoid calling shell scripts directly. If necessary, use child_process.execFile or spawn with clean arguments array instead of raw string shell commands.',
    safeCode: '// Vulnerable:\n// exec("ping -c 1 " + req.query.host);\n\n// Secure:\n// const { execFile } = require(\'child_process\');\n// execFile(\'/bin/ping\', [\' -c\', \'1\', req.query.host]);',
    pattern: /(?:exec|execSync|spawn|eval)\s*\(\s*.*(?:req\.query|req\.body|req\.params|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_])/i
  },
  {
    id: 'SEC-JWT-UNSAFE',
    title: 'Unsafe JWT Decoding',
    category: 'Authentication / Authorization Bypass',
    severity: 'High',
    cvss: 7.5,
    description: 'Decoding JWT payload using jwt.decode() instead of verifying signature with jwt.verify().',
    danger: 'Attackers can forge token payloads (e.g., changing role to "admin") and bypass auth checks since signature validation is skipped.',
    fix: 'Always verify token signature using jwt.verify() alongside a secure secret key.',
    safeCode: '// Vulnerable:\n// const user = jwt.decode(token);\n\n// Secure:\n// const user = jwt.verify(token, process.env.JWT_SECRET);',
    pattern: /(?:\.decode\s*\(\s*token|jwt\.decode\s*\()/i
  },
  {
    id: 'SEC-PATH-TRAVERSAL',
    title: 'Arbitrary File System Read (Path Traversal)',
    category: 'Path Traversal',
    severity: 'High',
    cvss: 7.5,
    description: 'Directly feeding user-supplied filenames or routes into file system read APIs (like fs.readFile) without safety path checks.',
    danger: 'Allows malicious users to read sensitive server configuration files (like /etc/passwd or config.json) through directory traversal (../) attacks.',
    fix: 'Resolve paths safely using path.resolve/join and verify that the target path remains inside the designated downloads directory.',
    safeCode: '// Vulnerable:\n// fs.readFileSync(__dirname + "/uploads/" + req.query.file);\n\n// Secure:\n// const safePath = path.resolve(__dirname, "uploads", path.basename(req.query.file));',
    pattern: /(?:readFile|readFileSync|createReadStream)\s*\(\s*.*(?:req\.query|req\.body|req\.params|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_])/i
  },
  {
    id: 'SEC-FILE-UPLOAD',
    title: 'Insecure File Upload Configuration',
    category: 'Insecure File Upload',
    severity: 'High',
    cvss: 8.0,
    description: 'Uploading files without verifying type extensions or saving them to publicly accessible web directories.',
    danger: 'Allows upload of malicious executable files (like .php, .jsp, or .sh) which can be run on the server to gain terminal access.',
    fix: 'Validate file MIME types/extensions against an allowlist, rename uploaded files dynamically, and store them outside the public web root.',
    safeCode: '// Vulnerable:\n// const upload = multer({ dest: \'uploads/\' });\n\n// Secure:\n// const fileFilter = (req, file, cb) => {\n//   if (file.mimetype === \'image/png\') cb(null, true);\n//   else cb(new Error(\'Invalid type\'), false);\n// };',
    pattern: /(?:multer\s*\(|upload\s*=\s*multer)/i
  }
];

/** Detect language and framework from code content. */
export function runRecon(code) {
  let language = 'unknown';
  let framework = 'unknown';

  if (code.includes('import ') || code.includes('require(') || code.includes('console.log')) {
    language = 'JavaScript/TypeScript';
  } else if (code.includes('def ') || (code.includes('import ') && code.includes('.py'))) {
    language = 'Python';
  } else if (code.includes('package main') || code.includes('func main()')) {
    language = 'Go';
  } else if (code.includes('public class ') || code.includes('System.out.println')) {
    language = 'Java';
  } else if (code.includes('using System;') || code.includes('Console.WriteLine')) {
    language = 'C#';
  }

  if (code.includes('react') || code.includes('useState') || code.includes('useEffect')) {
    framework = 'React';
  } else if (code.includes('express()') || code.includes("require('express')")) {
    framework = 'Express (Node.js)';
  } else if (code.includes('Flask(') || code.includes('import flask')) {
    framework = 'Flask';
  } else if (code.includes('django.')) {
    framework = 'Django';
  }

  return { language, framework };
}

/**
 * Run the full agentic scan pipeline on a single file's code (in-browser).
 * Mirrors the original orchestrator: Recon → Routing → Execution → Aggregation.
 * @returns {{ success, summary, recon, findings, agentLogs }}
 */
export function runScan(code, filename = 'pasted_code.js') {
  const logs = [];
  const log = (step, message, data = null) =>
    logs.push({ timestamp: new Date().toISOString(), step, message, data });

  log('INIT', `Starting analysis on file: ${filename}`);

  // --- STEP 1: RECON ---
  log('RECON_START', 'Scanning code file for language, framework, and patterns...');
  const recon = runRecon(code);
  const lines = code.split(/\r?\n/);

  const entryPoints = [];
  lines.forEach((line, idx) => {
    if (/(?:app|router)\.(?:get|post|put|delete|use|patch)\s*\(/.test(line)) {
      entryPoints.push({ line: idx + 1, detail: line.trim() });
    } else if (/def\s+[a-zA-Z0-9_]+\s*\(.*req.*res.*\)/.test(line) || /def\s+[a-zA-Z0-9_]+\s*\(.*request.*\)/.test(line)) {
      entryPoints.push({ line: idx + 1, detail: line.trim() });
    }
  });
  recon.entryPoints = entryPoints;
  log('RECON_COMPLETE', `Recon results: Language=${recon.language}, Framework=${recon.framework}, EntryPoints=${entryPoints.length}`, recon);

  // --- STEP 2: ROUTING ---
  log('ROUTING', 'Determining active scanner modules based on Recon metadata...');
  const activeModules = ['SEC-SECRET', 'SEC-WEAK-CRYPTO'];
  log('ROUTING_DECISION', 'Enabling global modules: Sensitive Data (Secrets) & Weak Cryptography');

  if (recon.language === 'JavaScript/TypeScript') {
    activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD');
    log('ROUTING_DECISION', 'Detected JS environment: Enabling SQLi, XSS, Cmd Injection, JWT Auth, Path Traversal, and Insecure Upload modules');
  } else if (recon.language === 'Python') {
    activeModules.push('SEC-SQLI', 'SEC-CMD-INJ', 'SEC-PATH-TRAVERSAL');
    log('ROUTING_DECISION', 'Detected Python environment: Enabling SQLi, Cmd Injection, and Path Traversal modules');
  } else {
    activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD');
    log('ROUTING_DECISION', 'Fallback: Enabling all scanner modules for general static parsing');
  }

  // --- STEP 3: EXECUTION ---
  log('EXECUTION_START', `Executing ${activeModules.length} selected scanner modules...`);
  const allFindings = [];
  const selectedRules = VULNERABILITY_RULES.filter(rule => activeModules.includes(rule.id));

  for (const rule of selectedRules) {
    log('MODULE_RUN', `Running scanner module: ${rule.title} (${rule.id})`);
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
      log('MODULE_RESULT', `Module ${rule.id} found ${findingsForModule.length} vulnerability instance(s)`, findingsForModule);
      allFindings.push(...findingsForModule);
    } else {
      log('MODULE_RESULT', `Module ${rule.id} completed. No vulnerabilities found.`);
    }
  }

  // --- STEP 4: AGGREGATION ---
  log('AGGREGATION', `Combining results. Total vulnerabilities found: ${allFindings.length}`);
  log('AGENT_COMPLETE', 'Agent run finished. Generating payload.');

  return {
    success: true,
    summary: {
      totalVulnerabilities: allFindings.length,
      language: recon.language,
      framework: recon.framework,
      entryPointsCount: entryPoints.length,
      timestamp: new Date().toISOString()
    },
    recon,
    findings: allFindings,
    agentLogs: logs
  };
}

/**
 * Scan multiple files and aggregate into one unified result.
 * @param {{name: string, code: string}[]} files
 */
export function scanFiles(files) {
  const allFindings = [];
  let last = null;
  const logs = [];

  for (const f of files) {
    const result = runScan(f.code, f.name);
    allFindings.push(...result.findings);
    logs.push(...result.agentLogs);
    last = result;
  }

  if (!last) return runScan('', 'empty');

  return {
    ...last,
    findings: allFindings,
    summary: {
      ...last.summary,
      totalVulnerabilities: allFindings.length,
      filesScanned: files.length
    },
    agentLogs: logs
  };
}
