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
 *
 * SSRF hardening — because this is a "fetch any URL" endpoint it is a prime SSRF
 * target. Defences:
 *   1. Only http/https schemes are accepted.
 *   2. The hostname is DNS-resolved and EVERY resolved IP is checked against
 *      loopback / private / link-local / CGNAT / reserved ranges (IPv4 + IPv6).
 *      Resolving the name also normalises exotic encodings (decimal/hex/octal
 *      IPs, IPv4-mapped IPv6) so they can't slip past a string check.
 *   3. Redirects are followed MANUALLY and every hop is re-validated, so a public
 *      URL cannot bounce us to 169.254.169.254 (cloud metadata) or localhost.
 */

import dns from 'node:dns/promises';
import net from 'node:net';

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 10000;

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n >>> 0;
}

/** True if an IPv4 address falls in a non-public range we must never reach. */
function isPrivateIPv4(ip) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  const inRange = (base, bits) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (ipv4ToInt(base) & mask);
  };
  return (
    inRange('0.0.0.0', 8) ||        // "this" network
    inRange('10.0.0.0', 8) ||       // private
    inRange('100.64.0.0', 10) ||    // carrier-grade NAT
    inRange('127.0.0.0', 8) ||      // loopback
    inRange('169.254.0.0', 16) ||   // link-local (incl. 169.254.169.254 metadata)
    inRange('172.16.0.0', 12) ||    // private
    inRange('192.0.0.0', 24) ||     // IETF protocol assignments
    inRange('192.168.0.0', 16) ||   // private
    inRange('198.18.0.0', 15) ||    // benchmarking
    n >= ipv4ToInt('224.0.0.0')     // multicast + reserved + broadcast
  );
}

/** True if an IPv6 address is loopback / link-local / unique-local / mapped-private. */
function isPrivateIPv6(ip) {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (a === '::1' || a === '::') return true;
  if (a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true; // link-local + ULA
  const mapped = a.match(/(?:::ffff:)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

function isPrivateAddr(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true; // unknown format → treat as unsafe
}

/**
 * Resolve the hostname and confirm it (and every IP it points at) is public.
 * Returns true only when the target is safe to fetch.
 */
async function isPublicHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return false;

  // Literal IP supplied directly.
  if (net.isIP(host)) return !isPrivateAddr(host);

  // Must look like a real domain name (rejects junk; numeric/hex forms are
  // resolved below via getaddrinfo which normalises them to a real IP).
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes('.')) return false;

  let addrs;
  try {
    addrs = await dns.lookup(host, { all: true });
  } catch {
    return false;
  }
  if (!addrs.length) return false;
  return addrs.every(({ address }) => !isPrivateAddr(address));
}

function normalizeUrl(raw) {
  let s = String(raw || '').trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return u;
}

/**
 * Fetch with manual redirect handling, re-validating the host on every hop so a
 * public URL cannot redirect us into a private/internal address.
 */
async function safeFetch(startUrl, signal) {
  let current = startUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!(await isPublicHost(current.hostname))) {
      const err = new Error('Target resolves to a private or blocked address.');
      err.code = 'BLOCKED_HOST';
      throw err;
    }

    const resp = await fetch(current.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VulnShield-HeaderScanner/1.0; +https://github.com/abdulrehmanh1678-hub/VULN-shield)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });

    const location = resp.headers.get('location');
    const isRedirect = resp.status >= 300 && resp.status < 400 && location;
    if (!isRedirect) {
      return { resp, finalUrl: current, redirected: hop > 0 };
    }

    let next;
    try { next = new URL(location, current); } catch {
      const err = new Error('Target returned an invalid redirect.');
      err.code = 'BAD_REDIRECT';
      throw err;
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      const err = new Error('Target redirected to a non-http(s) location.');
      err.code = 'BAD_REDIRECT';
      throw err;
    }
    current = next;
  }
  const err = new Error('Target exceeded the maximum number of redirects.');
  err.code = 'TOO_MANY_REDIRECTS';
  throw err;
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
    return res.status(400).json({ ok: false, error: 'Enter a valid public http(s) URL.' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const { resp: upstream, finalUrl, redirected } = await safeFetch(url, controller.signal);

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

    return res.status(200).json({
      ok: true,
      target: {
        requestedUrl: url.toString(),
        finalUrl: finalUrl.toString(),
        hostname: finalUrl.hostname,
        scheme: finalUrl.protocol.replace(':', ''),
        status: upstream.status,
        redirected,
        checkedAt: new Date().toISOString()
      },
      headers,
      setCookie
    });
  } catch (err) {
    let msg;
    if (err?.name === 'AbortError') {
      msg = 'Target did not respond within 10 seconds.';
    } else if (err?.code === 'BLOCKED_HOST') {
      msg = 'That host is not allowed — private, loopback, and internal addresses are blocked.';
    } else if (err?.code === 'BAD_REDIRECT' || err?.code === 'TOO_MANY_REDIRECTS') {
      msg = err.message;
    } else {
      msg = 'Could not reach the target (network error).';
    }
    return res.status(200).json({ ok: false, error: msg });
  } finally {
    clearTimeout(timeout);
  }
}

function safeParse(s) {
  try { return JSON.parse(s || '{}'); } catch { return {}; }
}
