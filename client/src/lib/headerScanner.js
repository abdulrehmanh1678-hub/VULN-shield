/**
 * Live HTTP Security-Header & Cookie Scanner (browser-side rules engine).
 *
 * Companion to scanner.js (which scans source code). This module scans a *deployed*
 * target: it asks the /api/headers serverless function to fetch the URL server-side
 * (browsers can't read cross-origin response headers), then grades the response
 * headers and cookies against OWASP "A05: Security Misconfiguration" best practice.
 *
 * Output shape mirrors scanner.js runScan() — { success, summary, recon, findings,
 * agentLogs } plus { headerScan, grade, score } — so the result flows unchanged
 * through ResultsViewer, AIReportViewer, history, and export.
 */

/**
 * Header rules. Each rule inspects the raw header map and returns a finding object
 * (same shape ResultsViewer expects) when the header is missing or weak, or null
 * when the target passes. `weight` feeds the letter-grade calculation.
 */
const HEADER_RULES = [
  {
    id: 'SEC-HDR-CSP',
    header: 'content-security-policy',
    title: 'Missing Content-Security-Policy',
    category: 'Security Misconfiguration',
    severity: 'Medium', cvss: 6.1, weight: 25,
    danger: 'Without a CSP, the browser has no defence-in-depth against cross-site scripting (XSS) or data-injection — a single reflected/stored XSS becomes fully exploitable, and the page can load scripts from any origin.',
    fix: 'Define a Content-Security-Policy that allowlists trusted script/style/connect sources and forbids inline script where possible. Start in report-only mode, then enforce.',
    safe: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    test: (h) => !h['content-security-policy']
  },
  {
    id: 'SEC-HDR-HSTS',
    header: 'strict-transport-security',
    title: 'Missing HTTP Strict-Transport-Security (HSTS)',
    category: 'Security Misconfiguration',
    severity: 'Medium', cvss: 5.9, weight: 20,
    danger: 'Without HSTS, a network attacker can strip TLS (SSL-stripping) on the first or a later visit and downgrade the connection to plaintext HTTP, intercepting credentials and session cookies.',
    fix: 'Send Strict-Transport-Security with a long max-age (≥ 6 months) and includeSubDomains; add preload once you are confident every subdomain is HTTPS-only.',
    safe: 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
    // Only meaningful over HTTPS; gated in scan() below.
    test: (h) => !h['strict-transport-security']
  },
  {
    id: 'SEC-HDR-XFO',
    header: 'x-frame-options',
    title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
    category: 'Security Misconfiguration',
    severity: 'Medium', cvss: 5.4, weight: 12,
    danger: 'The page can be embedded in a hidden iframe on an attacker-controlled site and used for clickjacking — tricking users into clicking actions (e.g. confirm payment, change settings) they never intended.',
    fix: "Send X-Frame-Options: DENY (or SAMEORIGIN) and/or a CSP frame-ancestors directive to control who may frame the page.",
    safe: "X-Frame-Options: DENY\n# or, preferred:\nContent-Security-Policy: frame-ancestors 'none'",
    // Passes if XFO present OR CSP already restricts frame-ancestors.
    test: (h) => !h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')
  },
  {
    id: 'SEC-HDR-XCTO',
    header: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options: nosniff',
    category: 'Security Misconfiguration',
    severity: 'Low', cvss: 3.1, weight: 6,
    danger: 'Browsers may MIME-sniff responses and execute a file served with the wrong Content-Type as a script — turning an uploaded "image" or text file into an XSS vector.',
    fix: 'Send X-Content-Type-Options: nosniff on every response so browsers honour the declared Content-Type.',
    safe: 'X-Content-Type-Options: nosniff',
    test: (h) => (h['x-content-type-options'] || '').toLowerCase().trim() !== 'nosniff'
  },
  {
    id: 'SEC-HDR-REFERRER',
    header: 'referrer-policy',
    title: 'Missing Referrer-Policy',
    category: 'Security Misconfiguration',
    severity: 'Low', cvss: 3.1, weight: 5,
    danger: 'Without a Referrer-Policy, full URLs (which may contain session tokens, reset links, or internal paths) leak to third-party sites and analytics in the Referer header.',
    fix: 'Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.',
    safe: 'Referrer-Policy: strict-origin-when-cross-origin',
    test: (h) => !h['referrer-policy']
  },
  {
    id: 'SEC-HDR-PERMISSIONS',
    header: 'permissions-policy',
    title: 'Missing Permissions-Policy',
    category: 'Security Misconfiguration',
    severity: 'Low', cvss: 2.4, weight: 4,
    danger: 'Powerful browser features (camera, microphone, geolocation, FLoC) are not restricted, widening the impact of any injected/third-party script that tries to abuse them.',
    fix: 'Send a Permissions-Policy that disables features the site does not use.',
    safe: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()',
    test: (h) => !h['permissions-policy']
  },
  {
    id: 'SEC-HDR-INFO-LEAK',
    header: 'server',
    title: 'Server / Technology Version Disclosure',
    category: 'Security Misconfiguration',
    severity: 'Low', cvss: 3.3, weight: 5,
    danger: 'Response headers advertise the exact server software and version, letting attackers map your stack to known CVEs and target the right exploits without any guesswork.',
    fix: 'Strip or obfuscate the Server and X-Powered-By headers at the web-server / framework level.',
    safe: '# Nginx:   server_tokens off;\n# Express:  app.disable("x-powered-by");',
    // Fires only when a version number is actually leaked.
    test: (h) => {
      const v = `${h['server'] || ''} ${h['x-powered-by'] || ''}`;
      return /\d+\.\d+/.test(v) || /x-powered-by/i.test(Object.keys(h).join(' '));
    },
    evidenceOf: (h) => [h['server'] && `Server: ${h['server']}`, h['x-powered-by'] && `X-Powered-By: ${h['x-powered-by']}`].filter(Boolean).join('  ·  ')
  }
];

/** Cookie rules — applied per Set-Cookie value. */
const COOKIE_RULES = [
  {
    id: 'SEC-COOKIE-SECURE',
    title: 'Cookie set without Secure flag',
    severity: 'Medium', cvss: 5.4, weight: 10,
    danger: 'A cookie without the Secure flag is transmitted over plaintext HTTP, where a network attacker can capture it — hijacking the user session.',
    fix: 'Add the Secure attribute so the cookie is only ever sent over HTTPS.',
    safe: 'Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax',
    test: (c) => !c.secure
  },
  {
    id: 'SEC-COOKIE-HTTPONLY',
    title: 'Cookie set without HttpOnly flag',
    severity: 'Medium', cvss: 5.0, weight: 8,
    danger: 'Without HttpOnly, the cookie is readable from JavaScript, so any XSS on the page can steal the session token directly via document.cookie.',
    fix: 'Add the HttpOnly attribute to session/auth cookies so they are invisible to JavaScript.',
    safe: 'Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax',
    test: (c) => !c.httpOnly
  },
  {
    id: 'SEC-COOKIE-SAMESITE',
    title: 'Cookie set with missing or weak SameSite',
    severity: 'Low', cvss: 3.5, weight: 5,
    danger: 'A cookie without SameSite=Lax/Strict is sent on cross-site requests, exposing the session to cross-site request forgery (CSRF).',
    fix: 'Set SameSite=Lax (or Strict for sensitive cookies). Only use SameSite=None with Secure for genuine cross-site needs.',
    safe: 'Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly',
    test: (c) => !c.sameSite || c.sameSite.toLowerCase() === 'none'
  }
];

function parseCookie(raw) {
  const parts = raw.split(';').map(s => s.trim());
  const name = (parts[0] || '').split('=')[0];
  const flags = parts.slice(1).map(s => s.toLowerCase());
  const sameSiteRaw = parts.slice(1).find(s => /^samesite=/i.test(s));
  return {
    name: name || '(unnamed)',
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: sameSiteRaw ? sameSiteRaw.split('=')[1] : null,
    raw
  };
}

const SEV_DEDUCT = { Critical: 40, High: 25, Medium: 12, Low: 5 };

function toGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

/**
 * Run the live header/cookie scan against a URL.
 * @returns {Promise<object>} scan result (same shape as scanner.runScan)
 */
export async function scanHeaders(rawUrl) {
  const logs = [];
  const log = (step, message, data = null) =>
    logs.push({ timestamp: new Date().toISOString(), step, message, data });

  log('INIT', `Starting live HTTP header scan: ${rawUrl}`);
  log('FETCH_START', 'Requesting target via /api/headers (server-side fetch)...');

  let data;
  try {
    const res = await fetch('/api/headers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl })
    });
    data = await res.json();
  } catch (err) {
    throw new Error('Header-scan API unreachable. On Vercel this works automatically; for local dev run `vercel dev` so /api functions are served.');
  }

  if (!data || !data.ok) {
    throw new Error(data?.error || 'The target could not be scanned.');
  }

  const { target, headers, setCookie = [] } = data;
  log('FETCH_COMPLETE', `Fetched ${target.finalUrl} — HTTP ${target.status}${target.redirected ? ' (redirected)' : ''}`, target);

  const findings = [];
  const isHttps = target.scheme === 'https';

  // --- Header rules ---
  log('RULES_HEADERS', `Evaluating ${HEADER_RULES.length} security-header rules...`);
  for (const rule of HEADER_RULES) {
    // HSTS only matters over HTTPS.
    if (rule.id === 'SEC-HDR-HSTS' && !isHttps) continue;
    if (!rule.test(headers)) continue;

    const present = headers[rule.header];
    const evidence = rule.evidenceOf
      ? rule.evidenceOf(headers)
      : present
        ? `${rule.header}: ${present}`
        : `Response header "${rule.header}" is not set`;

    findings.push({
      id: `${rule.id}-1`,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      cvss: rule.cvss,
      file: target.hostname,
      line: 0,
      evidence,
      description: `${rule.title} on ${target.finalUrl}.`,
      danger: rule.danger,
      fix: rule.fix,
      safeCode: rule.safe,
      _weight: rule.weight
    });
  }

  // --- Cookie rules ---
  if (setCookie.length) {
    log('RULES_COOKIES', `Evaluating ${setCookie.length} cookie(s) against ${COOKIE_RULES.length} rules...`);
    setCookie.forEach((raw, ci) => {
      const cookie = parseCookie(raw);
      // Secure flag only meaningful/penalised over HTTPS context.
      for (const rule of COOKIE_RULES) {
        if (rule.id === 'SEC-COOKIE-SECURE' && !isHttps) continue;
        if (!rule.test(cookie)) continue;
        findings.push({
          id: `${rule.id}-${ci + 1}`,
          title: `${rule.title} — "${cookie.name}"`,
          category: 'Security Misconfiguration',
          severity: rule.severity,
          cvss: rule.cvss,
          file: target.hostname,
          line: 0,
          evidence: cookie.raw,
          description: `Cookie "${cookie.name}" set by ${target.finalUrl} ${rule.title.toLowerCase()}.`,
          danger: rule.danger,
          fix: rule.fix,
          safeCode: rule.safe,
          _weight: rule.weight
        });
      }
    });
  } else {
    log('RULES_COOKIES', 'No Set-Cookie headers returned by the target.');
  }

  // --- Grade ---
  let score = 100;
  for (const f of findings) score -= (SEV_DEDUCT[f.severity] || 5);
  score = Math.max(0, Math.min(100, score));
  const grade = toGrade(score);
  log('GRADING', `Computed header grade ${grade} (score ${score}/100) from ${findings.length} issue(s).`);

  // Strip the internal weight field before returning.
  findings.forEach(f => { delete f._weight; });

  log('AGENT_COMPLETE', 'Header scan finished. Generating payload.');

  return {
    success: true,
    headerScan: true,
    grade,
    score,
    summary: {
      totalVulnerabilities: findings.length,
      language: 'HTTP Security Headers',
      framework: `${target.hostname} · Grade ${grade} (${score}/100)`,
      entryPointsCount: 0,
      timestamp: target.checkedAt
    },
    recon: {
      language: 'HTTP Security Headers',
      framework: target.hostname,
      target,
      entryPoints: []
    },
    findings,
    agentLogs: logs
  };
}
