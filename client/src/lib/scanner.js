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
    safeCode: '// Vulnerable:\n// db.query("SELECT * FROM users WHERE name = \'" + input + "\'");\n\n// Secure:\ndb.query("SELECT * FROM users WHERE name = ?", [input]);\n\n# Python (secure):\n# cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
    // Matches a SQL keyword combined with a dynamic-value indicator:
    // JS concat/template (`+ x`, `${x}`), Python f-string `{x}`, `%` / `.format()` formatting.
    // Two ways a SQL string becomes tainted:
    // (1) a SQL keyword followed by a dynamic indicator — JS concat/`${}`, Python `%`/.format();
    // (2) a Python f-string whose body contains a SQL keyword and a `{var}` interpolation
    //     (here the f-prefix sits *before* the keyword, so it needs its own branch).
    pattern: /(?:(?:select|insert|update|delete|where|join|from)\b.*(?:\+\s*[a-zA-Z_$]|\$\{|%\s*[a-zA-Z_(]|\.format\s*\(|concat\s*\())|(?:\bf["'`].*(?:select|insert|update|delete|where|from)\b.*\{[a-zA-Z_])/i
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
    safeCode: '// Vulnerable:\n// element.innerHTML = userInput;\n\n// Secure:\nimport DOMPurify from \'dompurify\';\nelement.innerHTML = DOMPurify.sanitize(userInput);\n// OR:\nelement.textContent = userInput;\n\n# Python/Jinja2 (secure): rely on autoescaping; avoid |safe / mark_safe on user input.',
    // JS DOM sinks + Python/Jinja templating sinks (render_template_string, mark_safe, Markup).
    pattern: /(?:innerHTML\s*=|\.dangerouslySetInnerHTML\s*=|document\.write\s*\(|render_template_string\s*\(|mark_safe\s*\(|\bMarkup\s*\()/i
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
    pattern: /(?:const|let|var|define)?.*(?:api_key|apikey|secret|password|passwd|private_key|token|access_key|jwt_secret)\s*=\s*['"`][a-zA-Z0-9_\-/+=]{10,}['"`]/i
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
    safeCode: '// Vulnerable:\n// crypto.createHash(\'md5\').update(password).digest(\'hex\');\n\n// Secure:\n// const bcrypt = require(\'bcrypt\');\n// await bcrypt.hash(password, 10);\n\n# Python (secure):\n# import bcrypt; bcrypt.hashpw(pw.encode(), bcrypt.gensalt())',
    // JS createHash('md5'|'sha1') and bare md5()/sha1(); Python hashlib.md5()/hashlib.sha1().
    pattern: /(?:createHash\s*\(\s*['"`](?:md5|sha1)['"`]\)|hashlib\.(?:md5|sha1)\s*\(|\bmd5\s*\(|\bsha1\s*\()/i
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
    safeCode: '// Vulnerable:\n// exec("ping -c 1 " + req.query.host);\n\n// Secure:\n// const { execFile } = require(\'child_process\');\n// execFile(\'/bin/ping\', [\' -c\', \'1\', req.query.host]);\n\n# Python (secure):\n# subprocess.run(["ping", "-c", "1", host], shell=False)',
    // JS exec/spawn/eval and Python os.system/os.popen/subprocess.* combined with a tainted/dynamic arg.
    pattern: /(?:exec|execSync|execFile|spawn|eval|os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(\s*.*(?:req\.query|req\.body|req\.params|request\.(?:args|form|values)|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_]|f["'`].*\{[a-zA-Z_]|%\s*[a-zA-Z_(]|shell\s*=\s*True)/i
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
    safeCode: '// Vulnerable:\n// const user = jwt.decode(token);\n\n// Secure:\n// const user = jwt.verify(token, process.env.JWT_SECRET);\n\n# Python (secure):\n# jwt.decode(token, key, algorithms=["HS256"])  # never verify_signature=False',
    // JS jwt.decode (vs verify); Python PyJWT only when signature verification is explicitly disabled.
    pattern: /(?:\.decode\s*\(\s*token|jwt\.decode\s*\(|verify\s*=\s*False|verify_signature["'\s]*[:=]\s*False)/i
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
    safeCode: '// Vulnerable:\n// fs.readFileSync(__dirname + "/uploads/" + req.query.file);\n\n// Secure:\n// const safePath = path.resolve(__dirname, "uploads", path.basename(req.query.file));\n\n# Python (secure):\n# safe = os.path.join(BASE, os.path.basename(req_file)); open(safe)',
    // JS fs read APIs + Python open()/send_file with a tainted/dynamic path argument.
    pattern: /(?:readFile|readFileSync|createReadStream|res\.sendFile|sendFile|\bopen|send_file)\s*\(\s*.*(?:req\.query|req\.body|req\.params|request\.(?:args|form|values)|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_]|f["'`].*\{[a-zA-Z_]|%\s*[a-zA-Z_(])/i
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
  },
  {
    id: 'SEC-SSRF',
    title: 'Potential Server-Side Request Forgery (SSRF)',
    category: 'Server-Side Request Forgery',
    severity: 'High',
    cvss: 7.5,
    description: 'An outbound HTTP request is built from user-controlled input, letting an attacker control the destination URL.',
    danger: 'Attackers can force the server to reach internal services, cloud metadata endpoints (169.254.169.254), or scan the internal network — often leaking credentials.',
    fix: 'Validate and allowlist the target host/scheme, resolve and block private/link-local IP ranges, and never pass raw user input as a URL.',
    safeCode: '// Vulnerable:\n// axios.get(req.query.url);\n\n// Secure:\n// const host = new URL(req.query.url).hostname;\n// if (!ALLOWED_HOSTS.has(host)) throw new Error("blocked");\n// axios.get(`https://${host}/...`);',
    pattern: /(?:axios(?:\.(?:get|post|put|delete))?|fetch|got|http\.get|https\.get|requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|urlopen)\s*\(\s*.*(?:req\.query|req\.body|req\.params|request\.(?:args|form|values)|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_]|f["'`].*\{[a-zA-Z_])/i
  },
  {
    id: 'SEC-DESERIAL',
    title: 'Insecure Deserialization',
    category: 'Insecure Deserialization',
    severity: 'Critical',
    cvss: 9.8,
    description: 'Untrusted data is deserialized with an unsafe loader (pickle, yaml.load, marshal) that can instantiate arbitrary objects.',
    danger: 'Crafted serialized payloads can trigger remote code execution the moment they are loaded, fully compromising the host.',
    fix: 'Never deserialize untrusted input with pickle/marshal. Use yaml.safe_load(), and prefer plain JSON for data interchange.',
    safeCode: '# Vulnerable:\n# data = pickle.loads(request.data)\n# cfg = yaml.load(stream)\n\n# Secure:\n# import json; data = json.loads(request.data)\n# cfg = yaml.safe_load(stream)',
    pattern: /(?:pickle\.loads?\s*\(|cPickle\.loads?\s*\(|_pickle\.loads?\s*\(|marshal\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe))/i
  },
  {
    id: 'SEC-CORS-WILD',
    title: 'Permissive CORS Configuration',
    category: 'Security Misconfiguration',
    severity: 'Medium',
    cvss: 5.3,
    description: 'Cross-Origin Resource Sharing is configured with a wildcard origin (`*`) or reflects any origin, often alongside credentials.',
    danger: 'Any website can make authenticated cross-origin requests to your API, enabling theft of user data via the victim\'s browser session.',
    fix: 'Set an explicit allowlist of trusted origins. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.',
    safeCode: '// Vulnerable:\n// app.use(cors({ origin: "*" }));\n\n// Secure:\n// app.use(cors({ origin: ["https://app.example.com"], credentials: true }));',
    pattern: /(?:Access-Control-Allow-Origin["'\s:,]+\*|cors\s*\(\s*\{[^}]*origin\s*:\s*['"`]\*|origin\s*:\s*true|CORS_ORIGIN_ALLOW_ALL\s*=\s*True)/i
  },
  {
    id: 'SEC-OPEN-REDIRECT',
    title: 'Open Redirect',
    category: 'Broken Access Control',
    severity: 'Medium',
    cvss: 6.1,
    description: 'A redirect target is taken directly from user input without validating it points to a trusted destination.',
    danger: 'Attackers craft links on your trusted domain that bounce victims to phishing or malware sites, lending credibility to the attack.',
    fix: 'Redirect only to a fixed set of internal paths or an allowlist of hosts. Reject absolute URLs and protocol-relative (//) targets from user input.',
    safeCode: '// Vulnerable:\n// res.redirect(req.query.next);\n\n// Secure:\n// const ALLOWED = { dashboard: "/app" };\n// res.redirect(ALLOWED[req.query.next] || "/");',
    pattern: /(?:res\.redirect|response\.redirect|\bredirect|sendRedirect)\s*\(\s*.*(?:req\.query|req\.body|req\.params|request\.(?:args|form|values)|\+\s*[a-zA-Z_]|\$\{[a-zA-Z_]|f["'`].*\{[a-zA-Z_])/i
  },
  {
    id: 'SEC-NOSQL',
    title: 'Potential NoSQL Injection',
    category: 'Injection',
    severity: 'High',
    cvss: 8.1,
    description: 'User input is passed directly into a NoSQL query object (e.g. MongoDB find/$where), allowing operator injection.',
    danger: 'Attackers inject query operators ($ne, $gt, $where) to bypass authentication or exfiltrate arbitrary documents from the database.',
    fix: 'Cast inputs to expected primitive types before querying, and reject objects where a string is expected. Avoid $where with user input.',
    safeCode: '// Vulnerable:\n// User.findOne({ user: req.body.user, pass: req.body.pass });\n\n// Secure:\n// User.findOne({ user: String(req.body.user) });\n// then verify the hashed password separately',
    pattern: /(?:\.find|\.findOne|\.update(?:One|Many)?|\.remove|\.deleteOne)\s*\(\s*\{[^}]*(?:req\.(?:body|query|params)|request\.(?:args|form|json)|\$where)/i
  }
];

/** Detect language and framework from code content. */
export function runRecon(code) {
  let language = 'unknown';
  let framework = 'unknown';

  // Check distinctive markers first. NOTE: a bare `import ` is ambiguous (ES modules
  // AND Python use it), so JS is identified by JS-only tokens (require/console.log/=>,
  // `const`, or `import ... from '...'`) before falling through to Python.
  const jsSignal = /\b(?:const|let|function)\b/.test(code) || code.includes('require(') ||
    code.includes('console.log') || code.includes('=>') || /import\s+[^;]*\sfrom\s+['"]/.test(code);
  const pySignal = /\bdef\s+\w+\s*\(/.test(code) || /^\s*(?:from\s+[\w.]+\s+)?import\s+\w+/m.test(code) ||
    code.includes('elif ') || code.includes('print(') || code.includes('__name__');

  if (jsSignal) {
    language = 'JavaScript/TypeScript';
  } else if (pySignal) {
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
    } else if (/@(?:app|bp|blueprint|router)\.(?:route|get|post|put|delete|patch)\s*\(/.test(line)) {
      // Flask / FastAPI / Blueprint route decorators
      entryPoints.push({ line: idx + 1, detail: line.trim() });
    } else if (/^\s*(?:path|url|re_path)\s*\(/.test(line)) {
      // Django urlpatterns entries
      entryPoints.push({ line: idx + 1, detail: line.trim() });
    } else if (/def\s+[a-zA-Z0-9_]+\s*\(.*req.*res.*\)/.test(line) || /def\s+[a-zA-Z0-9_]+\s*\(.*request.*\)/.test(line)) {
      entryPoints.push({ line: idx + 1, detail: line.trim() });
    }
  });
  recon.entryPoints = entryPoints;
  log('RECON_COMPLETE', `Recon results: Language=${recon.language}, Framework=${recon.framework}, EntryPoints=${entryPoints.length}`, recon);

  // --- STEP 2: ROUTING ---
  log('ROUTING', 'Determining active scanner modules based on Recon metadata...');
  // Global modules run regardless of language (language-agnostic patterns).
  const activeModules = ['SEC-SECRET', 'SEC-WEAK-CRYPTO', 'SEC-CORS-WILD'];
  log('ROUTING_DECISION', 'Enabling global modules: Secrets, Weak Cryptography & CORS Misconfiguration');

  if (recon.language === 'JavaScript/TypeScript') {
    activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD',
      'SEC-SSRF', 'SEC-OPEN-REDIRECT', 'SEC-NOSQL', 'SEC-DESERIAL');
    log('ROUTING_DECISION', 'Detected JS environment: Enabling SQLi, XSS, Cmd Injection, JWT, Path Traversal, Insecure Upload, SSRF, Open Redirect, NoSQL Injection, and Insecure Deserialization modules');
  } else if (recon.language === 'Python') {
    activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL',
      'SEC-SSRF', 'SEC-OPEN-REDIRECT', 'SEC-DESERIAL');
    log('ROUTING_DECISION', 'Detected Python environment: Enabling SQLi, XSS (templates), Cmd Injection, JWT, Path Traversal, SSRF, Open Redirect, and Insecure Deserialization modules');
  } else {
    activeModules.push('SEC-SQLI', 'SEC-XSS-DOM', 'SEC-CMD-INJ', 'SEC-JWT-UNSAFE', 'SEC-PATH-TRAVERSAL', 'SEC-FILE-UPLOAD',
      'SEC-SSRF', 'SEC-OPEN-REDIRECT', 'SEC-NOSQL', 'SEC-DESERIAL');
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
