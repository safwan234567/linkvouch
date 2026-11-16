// Network helpers with SSRF protection. User-supplied URLs are only ever probed
// (status + Location header); response bodies are never downloaded.
import http from 'node:http';
import https from 'node:https';
import { BlockList, isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

const UA = 'Mozilla/5.0 (compatible; LinkGuard/0.1; link-safety-checker)';
const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

const blocked = new BlockList();
const V4: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
];
for (const [a, p] of V4) blocked.addSubnet(a, p, 'ipv4');
const V6: [string, number][] = [['::', 127], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32], ['64:ff9b::', 96]];
for (const [a, p] of V6) blocked.addSubnet(a, p, 'ipv6');

export function isPrivateAddress(ip: string): boolean {
  let addr = ip.replace(/^\[|\]$/g, '');
  const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) addr = mapped[1];
  const fam = isIP(addr);
  if (fam === 0) return true; // not an IP at all: treat as unsafe
  return blocked.check(addr, fam === 4 ? 'ipv4' : 'ipv6');
}

export type Address = { address: string; family: number };
export type Resolver = (host: string) => Promise<Address[]>;
const dnsResolver: Resolver = (host) => lookup(host, { all: true });

const HOP_TIMEOUT_MS = 6000;

/** Rejects when the signal fires, so a slow DNS lookup cannot outlive the hop's time limit. */
function withDeadline<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new Error('timed out')), { once: true });
    p.then(resolve, reject);
  });
}

/**
 * Throws unless the URL is http(s), on a normal web port, and resolves only to public addresses.
 * Returns the addresses that were checked. The caller must connect to exactly these (see probe),
 * never look the name up again: a second lookup could return a different, internal address (DNS rebinding).
 */
export async function assertPublicUrl(u: URL, resolve: Resolver = dnsResolver): Promise<Address[]> {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`blocked: scheme ${u.protocol}`);
  if (!ALLOWED_PORTS.has(u.port)) throw new Error(`blocked: port ${u.port}`);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const fam = isIP(host);
  if (fam) {
    if (isPrivateAddress(host)) throw new Error('blocked: private or reserved address');
    return [{ address: host, family: fam }];
  }
  const addrs = await resolve(host);
  if (!addrs.length) throw new Error('could not resolve host');
  if (addrs.some((a) => isPrivateAddress(a.address))) throw new Error('blocked: resolves to a private or reserved address');
  return addrs;
}

/**
 * One GET to the URL, connecting only to the given (already checked) addresses. The hostname is still
 * used for the Host header and for HTTPS certificate checks. Reads the status and Location header, never the body.
 */
export function probe(u: URL, pinned: Address[], signal: AbortSignal): Promise<{ status: number; location: string | null }> {
  return new Promise((resolve, reject) => {
    // Node asks this function for the address instead of doing its own DNS lookup.
    const pinnedLookup = (_host: string, opts: any, cb: any) => (opts?.all ? cb(null, pinned) : cb(null, pinned[0].address, pinned[0].family));
    const req = (u.protocol === 'https:' ? https : http).request(u, {
      method: 'GET', agent: false, lookup: pinnedLookup, signal,
      headers: { 'user-agent': UA, accept: 'text/html,*/*;q=0.5' },
    }, (res) => {
      const loc = res.headers.location;
      resolve({ status: res.statusCode ?? 0, location: typeof loc === 'string' ? loc : null });
      res.destroy(); // discard the body
    });
    req.on('error', reject);
    req.end();
  });
}

export type Hop = { url: string; status: number | null; error?: string };

/** Follows redirects by hand (max 5), re-validating every hop and pinning its checked address. Never reads a body. */
export async function followRedirects(start: string, maxHops = 5, resolve: Resolver = dnsResolver): Promise<Hop[]> {
  const chain: Hop[] = [];
  let current = start;
  for (let i = 0; i <= maxHops; i++) {
    let u: URL;
    try { u = new URL(current); } catch { chain.push({ url: current, status: null, error: 'invalid URL' }); break; }
    u.username = ''; u.password = '';
    try {
      const signal = AbortSignal.timeout(HOP_TIMEOUT_MS);
      const pinned = await withDeadline(assertPublicUrl(u, resolve), signal);
      const res = await probe(u, pinned, signal);
      chain.push({ url: u.href, status: res.status });
      if (res.status >= 300 && res.status < 400 && res.location) { current = new URL(res.location, u).href; continue; }
    } catch (e) {
      chain.push({ url: u.href, status: null, error: e instanceof Error ? e.message : String(e) });
    }
    break;
  }
  return chain;
}

// Public APIs (Wikimedia in particular) ask for a descriptive client name. Set LINKGUARD_CONTACT to your repo URL when hosting.
const API_UA = `LinkGuard/0.1 (open-source MCP link-safety checker${process.env.LINKGUARD_CONTACT ? '; ' + process.env.LINKGUARD_CONTACT : ''})`;
const cache = new Map<string, { at: number; value: any }>();
const CACHE_MS = 60 * 60 * 1000;

/** JSON from a fixed, trusted API host (registries, RDAP, Wikidata). Returns null on 404. Cached for an hour; retries once on 429. */
export async function getJson(url: string, timeoutMs = 9000): Promise<any | null> {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.value;
  let res: Response | undefined;
  for (let attempt = 0; attempt < 3; attempt++) {
    res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': API_UA, accept: 'application/json' } });
    if (res.status !== 429) break;
    res.body?.cancel().catch(() => {});
    const wait = Math.min(Number(res.headers.get('retry-after')) || 1, 3);
    await new Promise((r) => setTimeout(r, wait * 1000 + 200));
  }
  if (res!.status === 404) { res!.body?.cancel().catch(() => {}); cache.set(url, { at: Date.now(), value: null }); return null; }
  if (!res!.ok) throw new Error(`${new URL(url).hostname} answered ${res!.status}`);
  const value = await res!.json();
  if (cache.size > 500) cache.clear();
  cache.set(url, { at: Date.now(), value });
  return value;
}

/** Days since the domain was registered, via RDAP. null when the registry does not publish it. */
export async function domainAgeDays(domain: string): Promise<{ days: number; registered: string } | null> {
  try {
    const j = await getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, 7000);
    const ev = (j?.events ?? []).find((e: any) => e.eventAction === 'registration');
    if (!ev?.eventDate) return null;
    const t = Date.parse(ev.eventDate);
    if (Number.isNaN(t)) return null;
    return { days: Math.floor((Date.now() - t) / 86400000), registered: new Date(t).toISOString().slice(0, 10) };
  } catch { return null; }
}
