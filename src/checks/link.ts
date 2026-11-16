import { domainToUnicode } from 'node:url';
import { parse as parseDomain } from 'tldts';
import { BRANDS, RISKY_TLDS, SHORTENERS, brandForDomain } from '../lib/brands.ts';
import { domainAgeDays, followRedirects } from '../lib/net.ts';
import type { Hop } from '../lib/net.ts';
import { hasNonAscii, isAdjacentSwap, levenshtein, skeleton } from '../lib/text.ts';

export type Severity = 'high' | 'medium' | 'low' | 'info';
export type Finding = { severity: Severity; code: string; detail: string };
export type Verdict = 'high_risk' | 'suspicious' | 'no_red_flags' | 'known_official_domain' | 'invalid';

export type LinkReport = {
  input: string;
  url: string | null;
  hostname: string | null;
  registrable_domain: string | null;
  verdict: Verdict;
  risk_score: number;
  official_domain_of: string | null;
  domain_registered: string | null;
  domain_age_days: number | null;
  redirect_chain: Hop[];
  findings: Finding[];
  advice: string;
  limits: string;
};

const WEIGHT: Record<Severity, number> = { high: 50, medium: 20, low: 8, info: 0 };
const LIMITS = 'Heuristic check only. "no_red_flags" does not prove a site is safe: a brand-new scam can pass. Page content is never downloaded.';

/** Undo common "defanging" (hxxp://, example[.]com) and add a scheme if missing. */
export function normalizeUrl(raw: string): URL | null {
  let s = raw.trim().replace(/^<|>$/g, '').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/^hxxp/i, 'http').replace(/\[:\]/g, ':');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  try {
    const u = new URL(s);
    return u.hostname.includes('.') || u.hostname.includes(':') ? u : null;
  } catch { return null; }
}

/** Checks that need no network: the shape of the hostname itself. */
export function analyzeHost(u: URL): { findings: Finding[]; domain: string | null; official: string | null } {
  const findings: Finding[] = [];
  const host = u.hostname.toLowerCase();
  const p = parseDomain(host);

  if (p.isIp) {
    findings.push({ severity: 'high', code: 'ip_address_host', detail: `The link goes to a raw IP address (${host}) instead of a named website. Real services almost never do this.` });
    return { findings, domain: null, official: null };
  }
  const domain = p.domain;
  if (!domain || !p.publicSuffix) {
    findings.push({ severity: 'medium', code: 'unknown_domain_ending', detail: `"${host}" does not end in a recognised public domain ending.` });
    return { findings, domain: null, official: null };
  }

  const official = brandForDomain(domain);
  const unicodeHost = domainToUnicode(host);
  const label = p.domainWithoutSuffix ?? '';
  const uniLabel = domainToUnicode(domain).split('.')[0];

  if (host.includes('xn--') || hasNonAscii(unicodeHost)) {
    const sk = skeleton(uniLabel);
    const brand = BRANDS.find((b) => b.keywords.includes(sk));
    findings.push(brand && !official
      ? { severity: 'high', code: 'homoglyph_brand', detail: `The domain displays as "${unicodeHost}", using look-alike letters from another alphabet to imitate ${brand.name}. It is really "${host}".` }
      : { severity: 'medium', code: 'non_ascii_domain', detail: `The domain uses non-English characters (displays as "${unicodeHost}", really "${host}"). This can be legitimate, but is also used to fake familiar names.` });
  }

  if (!official) {
    const rawTokens = host.split(/[.\-]/).filter(Boolean);
    const skTokens = rawTokens.map(skeleton);
    const flat = skeleton(label.replace(/-/g, ''));
    let hit: Finding | null = null;
    for (const b of BRANDS) {
      // The real domain pasted in front of a different one: dbs.com.sg.evil.xyz
      const embedded = b.domains.find((d) => host.startsWith(d + '.') || host.includes('.' + d + '.'));
      if (embedded) { hit = { severity: 'high', code: 'official_domain_as_subdomain', detail: `"${embedded}" appears at the start of the address, but the site you would actually visit is "${domain}". This is a classic trick to imitate ${b.name}.` }; break; }
      for (const kw of b.keywords) {
        const exact = rawTokens.includes(kw), lookalike = !exact && skTokens.includes(kw);
        const near = kw.length >= 6 &&[flat, ...skTokens].some((t) => t !== kw && Math.abs(t.length - kw.length) <= 2 && (levenshtein(t, kw) <= (kw.length >= 8 ? 2 : 1) || isAdjacentSwap(t, kw)));
        let f: Finding | null = null;
        if (lookalike) f = { severity: 'high', code: 'lookalike_spelling', detail: `"${host}" uses look-alike characters to spell "${kw}" (${b.name}), but it is not one of ${b.name}'s domains (${b.domains.slice(0, 3).join(', ')}).` };
        else if (exact) f = { severity: kw.length <= 3 ? 'medium' : 'high', code: 'brand_name_on_other_domain', detail: `The address contains "${kw}" (${b.name}) but the real site is "${domain}", which is not a known ${b.name} domain (${b.domains.slice(0, 3).join(', ')}).` };
        else if (near) f = { severity: 'high', code: 'typo_of_brand', detail: `"${domain}" is one or two letters away from "${kw}" (${b.name}). Real domains: ${b.domains.slice(0, 3).join(', ')}.` };
        else if (kw.length >= 5 && flat.includes(kw)) f = { severity: 'medium', code: 'brand_name_inside_domain', detail: `The domain "${domain}" contains "${kw}" (${b.name}) but is not a known ${b.name} domain.` };
        if (f && (!hit || WEIGHT[f.severity] > WEIGHT[hit.severity])) hit = f;
      }
      if (hit?.severity === 'high') break;
    }
    if (hit) findings.push(hit);
  }

  if (SHORTENERS.has(domain)) findings.push({ severity: 'low', code: 'url_shortener', detail: `"${domain}" is a link shortener, which hides the real destination.` });
  if (RISKY_TLDS.has(p.publicSuffix.split('.').pop()!)) findings.push({ severity: 'low', code: 'cheap_tld', detail: `Domains ending in ".${p.publicSuffix}" are cheap and heavily used for scams (many legitimate sites use them too).` });
  if ((p.subdomain ?? '').split('.').filter(Boolean).length >= 4) findings.push({ severity: 'low', code: 'many_subdomains', detail: 'Unusually long chain of subdomains, often used to push the real domain out of view.' });
  if ((label.match(/-/g) ?? []).length >= 3) findings.push({ severity: 'low', code: 'many_hyphens', detail: 'The domain has many hyphens, a common pattern in throwaway scam domains.' });
  if (/(login|verify|secure|account|update|wallet|support|signin|banking|refund|claim)/i.test(label) && !official) findings.push({ severity: 'low', code: 'bait_words_in_domain', detail: 'The domain name itself contains words like "login", "verify" or "secure", which real companies rarely put in their domain.' });

  return { findings, domain, official: official?.name ?? null };
}

function verdictFrom(findings: Finding[], official: string | null): { verdict: Verdict; score: number } {
  const score = Math.min(100, findings.reduce((s, f) => s + WEIGHT[f.severity], 0));
  if (score >= 50) return { verdict: 'high_risk', score };
  if (score >= 20) return { verdict: 'suspicious', score };
  return { verdict: official ? 'known_official_domain' : 'no_red_flags', score };
}

/** Turns a "blocked: ..." error from the network guard into a finding that says what was actually blocked. */
export function blockedFinding(error: string): Finding {
  const port = error.match(/^blocked: port (\d+)/);
  if (port) return { severity: 'low', code: 'unusual_port', detail: `The link (or one of its redirects) uses port ${port[1]}. LinkVouch only contacts normal web ports, so this site was not contacted. Public websites rarely use unusual ports.` };
  const scheme = error.match(/^blocked: scheme (\S+)/);
  if (scheme) return { severity: 'low', code: 'non_web_redirect', detail: `The link redirects to a "${scheme[1]}" address, which is not a web page (it may open an app or another program). LinkVouch did not follow it.` };
  return { severity: 'high', code: 'internal_address', detail: `The link (or one of its redirects) points at a private or internal network address (${error}).` };
}

async function safeBrowsing(url: string): Promise<Finding | null> {
  const key = process.env.GSB_API_KEY;
  if (!key) return null;
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
      method: 'POST', signal: AbortSignal.timeout(6000), headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client: { clientId: 'linkvouch', clientVersion: '0.1' }, threatInfo: { threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'], platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] } }),
    });
    const j: any = await res.json();
    if (j?.matches?.length) return { severity: 'high', code: 'on_blocklist', detail: `Google Safe Browsing lists this URL as ${j.matches[0].threatType}.` };
  } catch { /* optional signal */ }
  return null;
}

export async function checkLink(raw: string, opts: { network?: boolean } = {}): Promise<LinkReport> {
  const network = opts.network !== false;
  const u = normalizeUrl(raw);
  const base = { input: raw, redirect_chain: [] as Hop[], domain_registered: null, domain_age_days: null, limits: LIMITS };
  if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) {
    return { ...base, url: null, hostname: null, registrable_domain: null, verdict: 'invalid', risk_score: 0, official_domain_of: null,
      findings: [{ severity: 'info', code: 'not_a_web_link', detail: 'This does not look like a web link (http/https).' }], advice: 'Nothing to check.' };
  }
  const findings: Finding[] = [];
  if (u.username || u.password) findings.push({ severity: 'high', code: 'at_sign_trick', detail: `The link has text before an "@" sign. Browsers ignore that part: the real destination is "${u.hostname}".` });
  if (raw.trim().toLowerCase().startsWith('http://')) findings.push({ severity: 'low', code: 'no_https', detail: 'The link uses http://, so the connection is not encrypted.' });

  const first = analyzeHost(u);
  findings.push(...first.findings);
  let official = first.official;
  let age: { days: number; registered: string } | null = null;
  let chain: Hop[] = [];

  if (network) {
    const clean = new URL(u.href); clean.username = ''; clean.password = '';
    const [c, a, gsb] = await Promise.all([followRedirects(clean.href), first.domain ? domainAgeDays(first.domain) : null, safeBrowsing(clean.href)]);
    chain = c; age = a;
    if (gsb) findings.push(gsb);
    const last = chain[chain.length - 1];
    if (last?.error?.startsWith('blocked')) findings.push(blockedFinding(last.error));
    else if (chain.length === 1 && last?.error) findings.push({ severity: 'info', code: 'unreachable', detail: `The site did not respond (${last.error}). It may be offline, taken down, or blocking automated checks.` });
    if (chain.length > 1 && last?.url) {
      const finalUrl = new URL(last.url);
      const fin = analyzeHost(finalUrl);
      if (fin.domain && fin.domain !== first.domain) {
        findings.push({ severity: fin.official ? 'info' : 'low', code: 'redirects_elsewhere', detail: `The link redirects to a different site: "${fin.domain}"${fin.official ? ` (a known ${fin.official} domain)` : ''}.` });
        for (const f of fin.findings) findings.push({ ...f, code: 'destination_' + f.code, detail: 'After redirecting: ' + f.detail });
        if (!fin.official) official = null;
        const a2 = await domainAgeDays(fin.domain);
        if (a2 && (!age || a2.days < age.days)) age = a2;
      }
      if (chain.length >= 4) findings.push({ severity: 'low', code: 'long_redirect_chain', detail: `The link bounces through ${chain.length - 1} redirects before landing.` });
    }
    if (age && !official) {
      if (age.days < 30) findings.push({ severity: 'high', code: 'very_new_domain', detail: `The domain was registered only ${age.days} day(s) ago (${age.registered}). Most phishing domains are days or weeks old.` });
      else if (age.days < 180) findings.push({ severity: 'medium', code: 'new_domain', detail: `The domain is only ${age.days} days old (registered ${age.registered}).` });
    }
  }

  const { verdict, score } = verdictFrom(findings, official);
  const advice = verdict === 'high_risk' ? 'Do not open this link or enter any details. If it claims to be from a company, go to that company by typing its official address yourself or using its app.'
    : verdict === 'suspicious' ? 'Treat with caution. Do not log in or pay through this link; reach the service through its official site or app instead.'
    : verdict === 'known_official_domain' ? `This is a known official domain of ${official}. Still check the full address in your browser before entering a password.`
    : 'No warning signs found, but that is not proof of safety. Be careful with logins, payments and downloads.';
  return { ...base, url: u.href, hostname: u.hostname, registrable_domain: first.domain, verdict, risk_score: score, official_domain_of: official,
    domain_registered: age?.registered ?? null, domain_age_days: age?.days ?? null, redirect_chain: chain, findings, advice };
}
