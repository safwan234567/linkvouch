import { parse as parseDomain } from 'tldts';
import { findBrandByName } from '../lib/brands.ts';
import { getJson } from '../lib/net.ts';
import { normalizeUrl } from './link.ts';

export type OfficialCandidate = { name: string; description: string | null; official_domains: string[]; source: string };
export type OfficialReport = {
  query: string;
  candidates: OfficialCandidate[];
  checked_url: string | null;
  checked_domain: string | null;
  match: 'match' | 'mismatch' | 'unknown' | 'not_checked';
  explanation: string;
  limits: string;
};

const domainOf = (url: string): string | null => {
  const u = normalizeUrl(url);
  return u ? parseDomain(u.hostname).domain : null;
};

async function wikidata(name: string): Promise<OfficialCandidate[]> {
  const s = await getJson(`https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&type=item&limit=4&search=${encodeURIComponent(name)}`);
  const ids: string[] = (s?.search ?? []).map((x: any) => x.id);
  if (!ids.length) return [];
  const e = await getJson(`https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=claims|labels|descriptions&languages=en&ids=${ids.join('|')}`);
  const out: OfficialCandidate[] = [];
  for (const id of ids) {
    const ent = e?.entities?.[id];
    const sites: string[] = (ent?.claims?.P856 ?? []).map((c: any) => c?.mainsnak?.datavalue?.value).filter(Boolean);
    const domains = [...new Set(sites.map(domainOf).filter((d): d is string => !!d))];
    if (domains.length) out.push({ name: ent?.labels?.en?.value ?? id, description: ent?.descriptions?.en?.value ?? null, official_domains: domains, source: `https://www.wikidata.org/wiki/${id}` });
  }
  return out;
}

export async function verifyOfficialSite(name: string, url?: string): Promise<OfficialReport> {
  const candidates: OfficialCandidate[] = [];
  const local = findBrandByName(name);
  if (local) candidates.push({ name: local.name, description: null, official_domains: local.domains, source: 'LinkVouch built-in brand list' });
  let wikidataFailed = false;
  try { candidates.push(...await wikidata(name)); } catch { wikidataFailed = true; }

  const limits = 'Official domains come from a small built-in list and from Wikidata (community-edited, property P856). Companies often own extra domains not listed there, so "mismatch" means "not confirmed", and name searches can return a different organisation with a similar name. Check the candidate descriptions.'
    + (wikidataFailed ? ' Wikidata could not be reached for this check.' : '');
  const checked = url ? domainOf(url) : null;
  if (!url) {
    return { query: name, candidates, checked_url: null, checked_domain: null, match: candidates.length ? 'not_checked' : 'unknown',
      explanation: candidates.length ? `Best-known official domain for "${name}": ${candidates[0].official_domains[0]}.` : `No official website found for "${name}".`, limits };
  }
  if (!checked) return { query: name, candidates, checked_url: url, checked_domain: null, match: 'unknown', explanation: 'The URL could not be parsed.', limits };
  if (!candidates.length) return { query: name, candidates, checked_url: url, checked_domain: checked, match: 'unknown', explanation: `No official website on record for "${name}", so "${checked}" cannot be confirmed either way.`, limits };
  const hit = candidates.find((c) => c.official_domains.includes(checked));
  return hit
    ? { query: name, candidates, checked_url: url, checked_domain: checked, match: 'match', explanation: `"${checked}" is a recorded official domain of ${hit.name} (${hit.source}).`, limits }
    : { query: name, candidates, checked_url: url, checked_domain: checked, match: 'mismatch', explanation: `"${checked}" is NOT among the recorded official domains for "${name}" (${candidates[0].official_domains.slice(0, 3).join(', ')}). Do not present it as the official site unless you can confirm it another way.`, limits };
}
