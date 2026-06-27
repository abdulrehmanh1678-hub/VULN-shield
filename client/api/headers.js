/**
 * Vercel Serverless Function — live HTTP response-header / cookie fetcher.
 *
 * Browsers cannot read arbitrary cross-origin response headers (CORS hides them),
 * so the actual fetch must happen server-side. This function takes a target URL,
 * fetches it, and returns the raw response headers + Set-Cookie values. All the
 * grading / rule logic lives client-side in src/lib/headerScanner.js so the rules
 * stay inspectable and testable alongside the static-analysis rules.
 *
 * GET  /api/headers              → { ok: true, ready: true }   (probe for the UI)
 * POST /api/headers  { url }     → { ok: true, target, headers, setCookie }
 *                                → { ok: false, error }        on failure
 */

const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']);

/** Reject loopback / private / link-local targets so this tool can't be used for SSRF. */
function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h)) return true;
  if (!h.includes('.') && !h.includes(':')) return true; // bare hostname (no TLD)
  // IPv4 private / link-local ranges
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

function normalizeUrl(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (isBlockedHost(u.hostname)) return null;
  return u;
}

export default async function handler(req, res) {
  if (req.method === 'GET') {
    return res.status(200).json({ ok: true, ready: true });
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const body = typeof req.body === 'string' ? safeParse(req.body) : (req.body || {});
  const url = normalizeUrl(body.url);
  if (!url) {
    return res.status(400).json({ ok: false, error: 'Enter a valid public http(s) URL (private/loopback hosts are blocked).' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const upstream = await fetch(url.toString(), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VulnShield-HeaderScanner/1.0; +https://github.com/abdulrehmanh1678-hub/VULN-shield)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });

    // Collect headers into a plain object (last value wins, except Set-Cookie).
    const headers = {};
    for (const [k, v] of upstream.headers.entries()) {
      if (k.toLowerCase() === 'set-cookie') continue;
      headers[k.toLowerCase()] = v;
    }

    // Set-Cookie needs special handling — there can be several.
    let setCookie = [];
    if (typeof upstream.headers.getSetCookie === 'function') {
      setCookie = upstream.headers.getSetCookie();
    } else if (typeof upstream.headers.raw === 'function') {
      setCookie = upstream.headers.raw()['set-cookie'] || [];
    } else {
      const sc = upstream.headers.get('set-cookie');
      if (sc) setCookie = [sc];
    }

    const finalUrl = new URL(upstream.url || url.toString());
    return res.status(200).json({
      ok: true,
      target: {
        requestedUrl: url.toString(),
        finalUrl: finalUrl.toString(),
        hostname: finalUrl.hostname,
        scheme: finalUrl.protocol.replace(':', ''),
        status: upstream.status,
        redirected: upstream.redirected === true,
        checkedAt: new Date().toISOString()
      },
      headers,
      setCookie
    });
  } catch (err) {
    const msg = err?.name === 'AbortError'
      ? 'Target did not respond within 10 seconds.'
      : `Could not reach the target (${err?.message || 'network error'}).`;
    return res.status(200).json({ ok: false, error: msg });
  } finally {
    clearTimeout(timeout);
  }
}

function safeParse(s) {
  try { return JSON.parse(s || '{}'); } catch { return {}; }
}
