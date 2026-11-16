// End-to-end test: starts the server over stdio, calls every tool through a real MCP client,
// and checks the verdicts. Needs internet (RDAP, registries, Wikidata).
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { isPrivateAddress } from '../src/lib/net.ts';

const client = new Client({ name: 'linkguard-smoke', version: '0.0.0' });
await client.connect(new StdioClientTransport({ command: process.execPath, args: ['src/stdio.ts'], stderr: 'ignore' }));

let failed = 0;
const call = async (name: string, args: Record<string, unknown>) => JSON.parse(((await client.callTool({ name, arguments: args })).content as any)[0].text);
const expect = (label: string, got: unknown, ok: boolean, extra = '') => {
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  ->  ${got}${extra ? '  ' + extra : ''}`);
};
const codes = (r: any) => (r.findings ?? []).map((f: any) => f.code).join(',');

const tools = (await client.listTools()).tools.map((t) => t.name).sort();
expect('tools listed', tools.join(','), tools.length === 5);

// ---- links
const linkCases: [string, string[], string?][] = [
  ['https://www.paypal.com/signin', ['known_official_domain']],
  ['paypa1-secure-login.com', ['high_risk'], 'lookalike_spelling'],
  ['http://dbs.com.sg.account-verify.xyz/login', ['high_risk'], 'official_domain_as_subdomain'],
  ['https://xn--pple-43d.com', ['high_risk'], 'homoglyph_brand'],
  ['hxxps://micros0ft-support[.]top/reset', ['high_risk'], 'lookalike_spelling'],
  ['https://paypal.com@198.51.100.7/a', ['high_risk'], 'at_sign_trick'],
  ['http://192.168.1.1/admin', ['high_risk'], 'internal_address'],
  ['https://www.wikipedia.org', ['no_red_flags']],
  ['https://www.singpass.gov.sg', ['known_official_domain']],
];
for (const [url, want, code] of linkCases) {
  const r = await call('check_link', { url });
  expect(`link ${url}`, r.verdict, want.includes(r.verdict) && (!code || codes(r).includes(code)), `[${codes(r)}] age=${r.domain_age_days}`);
}
const short = await call('check_link', { url: 'https://bit.ly/3xyzabc' });
expect('link shortener flagged', codes(short), codes(short).includes('url_shortener'));

// ---- messages
const scam = await call('check_message', { text: 'DBS: Your account has been suspended. Verify your OTP within 24 hours at http://dbs-secure-verify.com/login to avoid closure.' });
expect('message: bank scam SMS', scam.verdict, scam.verdict === 'high_risk' && codes(scam).includes('sg_bank_message_with_link'), `[${codes(scam)}]`);
const benign = await call('check_message', { text: 'Hey, are we still on for lunch at 1pm tomorrow? I booked the table.' });
expect('message: ordinary chat', benign.verdict, benign.verdict === 'no_red_flags');

// ---- official sites
const o1 = await call('verify_official_site', { name: 'DBS Bank', url: 'https://dbs-sg.com/login' });
expect('official: DBS vs dbs-sg.com', o1.match, o1.match === 'mismatch');
const o2 = await call('verify_official_site', { name: 'PayPal', url: 'https://www.paypal.com' });
expect('official: PayPal vs paypal.com', o2.match, o2.match === 'match');
const o3 = await call('verify_official_site', { name: 'Mozilla Firefox' });
expect('official: Wikidata lookup (Firefox)', JSON.stringify(o3.candidates.map((c: any) => c.official_domains[0])), o3.candidates.some((c: any) => c.official_domains.some((d: string) => /mozilla\.org|firefox\.com/.test(d))));

// ---- packages
const p1 = await call('check_package', { ecosystem: 'npm', name: 'react' });
expect('package: npm react', p1.verdict, p1.exists === true && p1.verdict === 'no_red_flags', `dl/wk=${p1.weekly_downloads} age=${p1.age_days}`);
const p2 = await call('check_package', { ecosystem: 'npm', name: 'linkguard-totally-made-up-pkg-93417' });
expect('package: hallucinated npm name', p2.verdict, p2.exists === false && p2.verdict === 'high_risk');
const p3 = await call('check_package', { ecosystem: 'pypi', name: 'requests' });
expect('package: pypi requests', p3.verdict, p3.exists === true && p3.verdict === 'no_red_flags', `dl/wk=${p3.weekly_downloads} age=${p3.age_days}`);
const p4 = await call('check_package', { ecosystem: 'pypi', name: 'reqeusts' });
expect('package: pypi typo "reqeusts"', p4.verdict, p4.similar_popular_package === 'requests' && p4.verdict !== 'no_red_flags', `exists=${p4.exists} [${codes(p4)}]`);

// ---- the headline tool
const v1 = await call('vet_ai_recommendation', { item: 'https://paypal-help-center.support/login', claimed_brand: 'PayPal' });
expect('vet: fake PayPal support link', v1.ok_to_recommend, v1.ok_to_recommend === false, v1.summary.slice(0, 90));
const v2 = await call('vet_ai_recommendation', { item: 'https://github.com/login', claimed_brand: 'GitHub' });
expect('vet: real GitHub login', v2.ok_to_recommend, v2.ok_to_recommend === true, v2.summary.slice(0, 90));
const v3 = await call('vet_ai_recommendation', { item: '+1 888 555 0199', claimed_brand: 'PayPal' });
expect('vet: support phone number', v3.ok_to_recommend, v3.kind === 'phone' && v3.ok_to_recommend === false);
const v4 = await call('vet_ai_recommendation', { item: 'linkguard-totally-made-up-pkg-93417', ecosystem: 'npm' });
expect('vet: hallucinated package', v4.ok_to_recommend, v4.ok_to_recommend === false);

// ---- SSRF guard (unit)
const priv = ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.5', '100.64.0.1', '::1', 'fd00::1', '::ffff:10.0.0.1', 'fe80::1'];
const pub = ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'];
expect('ssrf: private ranges blocked', priv.filter(isPrivateAddress).length, priv.every(isPrivateAddress));
expect('ssrf: public addresses allowed', pub.filter((a) => !isPrivateAddress(a)).length, pub.every((a) => !isPrivateAddress(a)));

await client.close();
console.log(failed ? `\n${failed} FAILED` : '\nall passed');
process.exit(failed ? 1 : 0);
