// Offline tests: no internet needed. They cover the network guard (SSRF and DNS rebinding)
// and the hostname checks that work without contacting anything.
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { blockedFinding, checkLink } from '../src/checks/link.ts';
import { assertPublicUrl, followRedirects, isPrivateAddress, probe } from '../src/lib/net.ts';
import type { Address } from '../src/lib/net.ts';

let failed = 0;
const expect = (label: string, got: unknown, ok: boolean) => {
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}  ->  ${got}`);
};

// ---- address filter
const priv = ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.5', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1', '::ffff:7f00:1', '[::1]', 'not-an-ip'];
const pub = ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'];
expect('filter: private and reserved addresses blocked', priv.filter(isPrivateAddress).length, priv.every(isPrivateAddress));
expect('filter: public addresses allowed', pub.filter((a) => !isPrivateAddress(a)).length, pub.every((a) => !isPrivateAddress(a)));

// ---- guard: a fake DNS resolver lets us test without real DNS
const fakeDns = (answers: Address[][]) => {
  const state = { calls: 0 };
  const resolve = async () => answers[Math.min(state.calls++, answers.length - 1)];
  return { state, resolve };
};
const PUBLIC: Address = { address: '8.8.8.8', family: 4 };
const LOOPBACK: Address = { address: '127.0.0.1', family: 4 };

const errorOf = async (p: Promise<unknown>) => { try { await p; return 'allowed'; } catch (e) { return (e as Error).message; } };

const a = fakeDns([[LOOPBACK]]);
const aErr = await errorOf(assertPublicUrl(new URL('http://evil.example/'), a.resolve));
expect('guard: name resolving to loopback is blocked', aErr, aErr.startsWith('blocked'));
const b = fakeDns([[PUBLIC, LOOPBACK]]);
const bErr = await errorOf(assertPublicUrl(new URL('http://mixed.example/'), b.resolve));
expect('guard: one internal address among public ones is blocked', bErr, bErr.startsWith('blocked') && b.state.calls === 1);
const c = fakeDns([[PUBLIC]]);
const checked = await assertPublicUrl(new URL('https://ok.example/'), c.resolve);
expect('guard: returns exactly the addresses it checked', JSON.stringify(checked), checked.length === 1 && checked[0].address === '8.8.8.8' && c.state.calls === 1);
const d = fakeDns([[PUBLIC]]);
const portErr = await errorOf(assertPublicUrl(new URL('http://ok.example:8000/'), d.resolve));
expect('guard: unusual port blocked before any DNS lookup', portErr, portErr === 'blocked: port 8000' && d.state.calls === 0);
const schemeErr = await errorOf(assertPublicUrl(new URL('ftp://ok.example/'), d.resolve));
expect('guard: non-web scheme blocked', schemeErr, schemeErr.startsWith('blocked: scheme') && d.state.calls === 0);
const mappedErr = await errorOf(assertPublicUrl(new URL('http://[::ffff:127.0.0.1]/')));
expect('guard: IPv4-mapped loopback literal blocked', mappedErr, mappedErr.startsWith('blocked'));

// ---- DNS rebinding: the connection must go to the checked address, with no second lookup.
// A local server stands in for "the checked address". The hostname ends in .invalid, which can never
// resolve, so the request can only succeed if probe() really connects to the pinned address.
const seen: { host?: string; path?: string }[] = [];
const local = http.createServer((req, res) => {
  seen.push({ host: req.headers.host, path: req.url });
  res.writeHead(302, { location: 'https://next.example/landing' }).end('x'.repeat(10_000));
});
await new Promise<void>((r) => local.listen(0, '127.0.0.1', r));
const port = (local.address() as AddressInfo).port;
const res = await probe(new URL(`http://pinned-host.invalid:${port}/path`), [LOOPBACK], AbortSignal.timeout(3000));
expect('pinning: probe connects to the pinned address', `${res.status} ${res.location}`, res.status === 302 && res.location === 'https://next.example/landing' && seen.length === 1);
expect('pinning: original hostname kept in the Host header', seen[0]?.host, seen[0]?.host === `pinned-host.invalid:${port}`);

// When the single lookup for a hop returns an internal address, the hop stops and nothing is contacted.
const rebind = fakeDns([[LOOPBACK]]);
const chain = await followRedirects('http://rebind.example/', 5, rebind.resolve);
expect('pinning: internal answer stops the hop, nothing is contacted', JSON.stringify(chain), chain.length === 1 && !!chain[0].error?.startsWith('blocked') && rebind.state.calls === 1 && seen.length === 1);
await new Promise((r) => local.close(r));

// ---- blocked reasons are labelled as what they are
expect('label: blocked port is not called an internal address', blockedFinding('blocked: port 8000').code, blockedFinding('blocked: port 8000').code === 'unusual_port' && blockedFinding('blocked: port 8000').severity === 'low');
expect('label: non-web redirect', blockedFinding('blocked: scheme mailto:').code, blockedFinding('blocked: scheme mailto:').code === 'non_web_redirect');
expect('label: private address', blockedFinding('blocked: private or reserved address').code, blockedFinding('blocked: private or reserved address').code === 'internal_address');
expect('label: name resolving to a private address', blockedFinding('blocked: resolves to a private or reserved address').severity, blockedFinding('blocked: resolves to a private or reserved address').severity === 'high');

// ---- hostname checks (network switched off)
const offline: [string, string, string?][] = [
  ['https://www.paypal.com/signin', 'known_official_domain'],
  ['paypa1-secure-login.com', 'high_risk', 'lookalike_spelling'],
  ['http://dbs.com.sg.account-verify.xyz/login', 'high_risk', 'official_domain_as_subdomain'],
  ['https://xn--pple-43d.com', 'high_risk', 'homoglyph_brand'],
  ['hxxps://micros0ft-support[.]top/reset', 'high_risk', 'lookalike_spelling'],
  ['https://paypal.com@198.51.100.7/a', 'high_risk', 'at_sign_trick'],
  ['https://www.wikipedia.org', 'no_red_flags'],
  ['not a link', 'invalid'],
];
for (const [url, want, code] of offline) {
  const r = await checkLink(url, { network: false });
  const codes = r.findings.map((f) => f.code).join(',');
  expect(`host ${url}`, `${r.verdict} [${codes}]`, r.verdict === want && (!code || codes.includes(code)));
}

console.log(failed ? `\n${failed} FAILED` : '\nall passed');
process.exit(failed ? 1 : 0);
