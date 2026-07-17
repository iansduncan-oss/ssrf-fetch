/**
 * SSRF-guarded fetch for user- or attacker-controlled URLs.
 *
 * Any time a server fetches a URL it did not author — a webhook target, an
 * image URL from a user profile, an OpenGraph/link-preview crawl, an SSRF-prone
 * "import from URL" feature — an attacker can point that URL at an internal
 * target: http://169.254.169.254/ (cloud metadata), http://localhost:6379
 * (Redis), http://10.0.0.5/ (a private service) — and have the server fetch it
 * from inside the private network. That's SSRF (Server-Side Request Forgery),
 * OWASP's #10.
 *
 * `safeFetch()` is a drop-in replacement for `fetch()` that:
 *   - requires http(s) (no file:, gopher:, etc.),
 *   - resolves the hostname and refuses to connect if ANY resolved address is
 *     loopback, link-local, private, unique-local, or CGNAT,
 *   - disables redirects (a public URL must not 30x-bounce to an internal one),
 *   - closes the DNS-rebinding / TOCTOU hole by pinning the connection to the
 *     exact addresses it just validated: the request runs on an undici Agent
 *     whose custom `lookup` returns only the pre-checked IPs, so a hostile DNS
 *     server can't return a public IP on the check and an internal one on the
 *     connect. The Host header / TLS SNI stay the original hostname, so
 *     certificate validation is unaffected.
 *
 * It returns a normal `Response`, so callers can `try/catch` and fall back
 * gracefully when a URL is blocked.
 */

import dns from 'node:dns/promises';
import net from 'node:net';
import { Agent } from 'undici';

function ipv4IsBlocked(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10/8 private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12 private
  if (a === 192 && b === 168) return true; // 192.168/16 private
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  return false;
}

function ipv6IsBlocked(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  // IPv4-mapped (::ffff:a.b.c.d) — validate the embedded v4
  const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return ipv4IsBlocked(mapped[1]);
  if (
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb')
  ) {
    return true; // fe80::/10 link-local
  }
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // fc00::/7 unique-local
  return false;
}

/**
 * Classifies a resolved IP address as internal (blocked) or public (allowed).
 * Exported for testing and for callers that want to validate an address
 * without issuing a request.
 */
export function addressIsBlocked(ip: string): boolean {
  if (net.isIPv4(ip)) return ipv4IsBlocked(ip);
  if (net.isIPv6(ip)) return ipv6IsBlocked(ip);
  return true; // unknown family → block
}

/**
 * A drop-in `fetch()` that refuses to connect to internal network targets and
 * pins the connection to the validated IP to defeat DNS rebinding.
 *
 * @param rawUrl The URL to fetch. Must be http(s).
 * @param init   Standard `RequestInit`. `redirect` is forced to `'error'`; a
 *               default 5s timeout is applied unless you pass your own `signal`.
 * @throws If the protocol is not http(s), or the hostname resolves to any
 *         internal address.
 */
export async function safeFetch(rawUrl: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(rawUrl);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`safeFetch: blocked protocol ${url.protocol}`);
  }

  // Resolve every address the hostname maps to and reject if any is internal.
  const records = await dns.lookup(url.hostname, { all: true });
  if (records.length === 0 || records.some((r) => addressIsBlocked(r.address))) {
    throw new Error(`safeFetch: blocked host ${url.hostname}`);
  }

  // Pin the connection to the exact addresses we just validated. undici calls
  // this lookup instead of re-resolving the name, so a DNS rebind between the
  // check above and the connect below can't substitute an internal IP (TOCTOU).
  const pinned = records.map((r) => ({ address: r.address, family: r.family }));
  // Short keep-alive so the per-call Agent's socket is reaped soon after the
  // response is read; the Agent itself is unreferenced afterward and GC'd (we
  // can't close() it here without risking aborting the caller's Response body).
  const dispatcher = new Agent({
    keepAliveTimeout: 1000,
    keepAliveMaxTimeout: 1000,
    connect: {
      lookup: (_hostname, options, callback) => {
        if (options && (options as { all?: boolean }).all) {
          return (callback as (e: null, a: typeof pinned) => void)(null, pinned);
        }
        return callback(null, pinned[0].address, pinned[0].family);
      },
    },
  });

  return fetch(rawUrl, {
    ...init,
    redirect: 'error', // a public URL must not redirect into an internal one
    signal: init.signal ?? AbortSignal.timeout(5000),
    // `dispatcher` is an undici extension to RequestInit honored by Node's fetch.
    dispatcher,
  } as RequestInit & { dispatcher: Agent });
}
