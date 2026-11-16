// Package checks for "slopsquatting": AI assistants sometimes invent package names, and attackers
// register those names (or near-typos of popular ones) with malware inside.
import { getJson } from '../lib/net.ts';
import { isAdjacentSwap, levenshtein } from '../lib/text.ts';
import type { Finding, Verdict } from './link.ts';

const POPULAR: Record<'npm' | 'pypi', string[]> = {
  npm: ['react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug', 'typescript', 'webpack', 'vite', 'next', 'vue', 'angular', 'svelte', 'jquery', 'moment', 'dayjs', 'uuid', 'dotenv', 'eslint', 'prettier', 'jest', 'mocha', 'vitest', 'babel-core', 'request', 'node-fetch', 'socket.io', 'mongoose', 'sequelize', 'prisma', 'tailwindcss', 'postcss', 'rollup', 'esbuild', 'nodemon', 'yargs', 'inquirer', 'zod', 'rxjs', 'redux', 'puppeteer', 'playwright', 'cheerio', 'sharp', 'bcrypt', 'jsonwebtoken', 'cors', 'body-parser', 'ws', 'pg', 'mysql2', 'redis', 'stripe', 'openai', 'langchain', 'three', 'electron', 'discord.js'],
  pypi: ['requests', 'numpy', 'pandas', 'scipy', 'matplotlib', 'flask', 'django', 'fastapi', 'pydantic', 'sqlalchemy', 'boto3', 'botocore', 'urllib3', 'certifi', 'setuptools', 'pip', 'wheel', 'pytest', 'pillow', 'beautifulsoup4', 'lxml', 'selenium', 'scrapy', 'tensorflow', 'torch', 'keras', 'scikit-learn', 'transformers', 'openai', 'anthropic', 'langchain', 'cryptography', 'pyyaml', 'jinja2', 'click', 'rich', 'tqdm', 'httpx', 'aiohttp', 'uvicorn', 'gunicorn', 'celery', 'redis', 'psycopg2', 'pymongo', 'python-dotenv', 'colorama', 'six', 'attrs', 'black', 'ruff', 'mypy', 'jupyter', 'notebook', 'seaborn', 'plotly', 'streamlit', 'opencv-python', 'pyjwt', 'paramiko', 'scapy'],
};

export type PackageReport = {
  ecosystem: 'npm' | 'pypi'; name: string; exists: boolean | null;
  verdict: Verdict; risk_score: number;
  created: string | null; age_days: number | null; versions: number | null; weekly_downloads: number | null;
  latest_version: string | null; repository: string | null; maintainers: number | null; registry_url: string;
  similar_popular_package: string | null; findings: Finding[]; advice: string; limits: string;
};

const flat = (s: string) => s.toLowerCase().replace(/[-_.]/g, '');
const WEIGHT = { high: 50, medium: 20, low: 8, info: 0 };
const LIMITS = 'Metadata check only. The package code is not scanned, so a clean result does not prove the package is safe. Popular-package comparison uses a short built-in list.';

function nearPopular(eco: 'npm' | 'pypi', name: string): string | null {
  const n = name.toLowerCase().replace(/^@[^/]+\//, '');
  if (POPULAR[eco].includes(n)) return null;
  for (const p of POPULAR[eco]) {
    if (flat(p) === flat(n)) return p;
    if (p.length >= 5 && isAdjacentSwap(n, p)) return p;
    if (p.length >= 5 && Math.abs(p.length - n.length) <= 2 && levenshtein(n, p) <= (p.length >= 9 ? 2 : 1)) return p;
    if (p.length >= 5 && [`${p}js`, `${p}-js`, `node-${p}`, `py${p}`, `python-${p}`, `${p}-python`, `${p}2`, `${p}-lib`, `${p}-utils`].includes(n)) return p;
  }
  return null;
}

export async function checkPackage(ecosystem: 'npm' | 'pypi', rawName: string): Promise<PackageReport> {
  const name = rawName.trim();
  const findings: Finding[] = [];
  const valid = ecosystem === 'npm' ? /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i.test(name) && name.length <= 214 : /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/i.test(name) && name.length <= 100;
  const registry_url = ecosystem === 'npm' ? `https://www.npmjs.com/package/${name}` : `https://pypi.org/project/${name}/`;
  const r: PackageReport = { ecosystem, name, exists: null, verdict: 'no_red_flags', risk_score: 0, created: null, age_days: null, versions: null, weekly_downloads: null,
    latest_version: null, repository: null, maintainers: null, registry_url, similar_popular_package: null, findings, advice: '', limits: LIMITS };
  if (!valid) {
    findings.push({ severity: 'info', code: 'invalid_name', detail: `"${name}" is not a valid ${ecosystem} package name.` });
    return { ...r, verdict: 'invalid', advice: 'Check the package name.' };
  }
  const similar = nearPopular(ecosystem, name);
  r.similar_popular_package = similar;

  let meta: any;
  try {
    meta = ecosystem === 'npm'
      ? await getJson(`https://registry.npmjs.org/${name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name)}`, 15000)
      : await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, 12000);
  } catch (e) {
    findings.push({ severity: 'info', code: 'registry_unreachable', detail: `Could not reach the ${ecosystem} registry (${e instanceof Error ? e.message : e}).` });
    return { ...r, advice: 'The registry could not be checked. Try again before installing.' };
  }

  if (!meta || (ecosystem === 'npm' && !meta.versions)) {
    r.exists = false;
    findings.push({ severity: 'high', code: 'package_does_not_exist', detail: `There is no ${ecosystem} package called "${name}". If an AI assistant suggested it, the name was probably invented (hallucinated). Attackers register such names later, so do not install it and do not publish under it.` });
    if (similar) findings.push({ severity: 'info', code: 'did_you_mean', detail: `The well-known package with a similar name is "${similar}".` });
    return { ...r, verdict: 'high_risk', risk_score: 60, advice: similar ? `Do not install "${name}". You probably want "${similar}".` : `Do not install "${name}". Find the real package from the project's official documentation.` };
  }
  r.exists = true;

  let created: number | null = null;
  if (ecosystem === 'npm') {
    created = Date.parse(meta.time?.created ?? '') || null;
    const latest = meta['dist-tags']?.latest;
    const v = meta.versions?.[latest] ?? {};
    r.latest_version = latest ?? null;
    r.versions = Object.keys(meta.versions ?? {}).length;
    r.maintainers = (meta.maintainers ?? []).length;
    const repo = v.repository?.url ?? meta.repository?.url ?? null;
    r.repository = typeof repo === 'string' ? repo.replace(/^git\+/, '').replace(/\.git$/, '') : null;
    const hooks = ['preinstall', 'install', 'postinstall'].filter((k) => v.scripts?.[k]);
    if (hooks.length) findings.push({ severity: 'medium', code: 'install_scripts', detail: `Runs code automatically on install (${hooks.map((k) => `${k}: "${String(v.scripts[k]).slice(0, 80)}"`).join('; ')}). Common in legitimate native packages, but also the usual way malicious packages execute.` });
    if (v.deprecated) findings.push({ severity: 'low', code: 'deprecated', detail: `The latest version is deprecated: ${String(v.deprecated).slice(0, 140)}` });
    try { r.weekly_downloads = (await getJson(`https://api.npmjs.org/downloads/point/last-week/${name}`))?.downloads ?? null; } catch { /* optional */ }
  } else {
    const times: number[] = Object.values(meta.releases ?? {}).flat().map((f: any) => Date.parse(f.upload_time_iso_8601 ?? f.upload_time ?? '')).filter((t) => !Number.isNaN(t));
    created = times.length ? Math.min(...times) : null;
    r.latest_version = meta.info?.version ?? null;
    r.versions = Object.keys(meta.releases ?? {}).length;
    const urls = meta.info?.project_urls ?? {};
    r.repository = Object.entries(urls).find(([k]) => /source|repo|github|code|homepage/i.test(k))?.[1] as string ?? meta.info?.home_page ?? null;
    try { r.weekly_downloads = (await getJson(`https://pypistats.org/api/packages/${encodeURIComponent(name.toLowerCase())}/recent`))?.data?.last_week ?? null; } catch { /* optional */ }
  }
  if (created) { r.created = new Date(created).toISOString().slice(0, 10); r.age_days = Math.floor((Date.now() - created) / 86400000); }

  const young = r.age_days !== null && r.age_days < 30, lowUse = r.weekly_downloads !== null && r.weekly_downloads < 500;
  if (young) findings.push({ severity: 'medium', code: 'very_new_package', detail: `First published only ${r.age_days} day(s) ago (${r.created}).` });
  else if (r.age_days !== null && r.age_days < 90) findings.push({ severity: 'low', code: 'new_package', detail: `First published ${r.age_days} days ago (${r.created}).` });
  if (lowUse) findings.push({ severity: 'low', code: 'few_downloads', detail: `Only about ${r.weekly_downloads} downloads in the last week.` });
  if (r.versions !== null && r.versions <= 1) findings.push({ severity: 'low', code: 'single_version', detail: 'Only one version has ever been published.' });
  if (!r.repository) findings.push({ severity: 'low', code: 'no_repository', detail: 'No source repository is linked, so the code is harder to review.' });
  if (similar) findings.push({ severity: young || lowUse ? 'high' : 'medium', code: 'similar_to_popular_package', detail: `The name is very close to the popular package "${similar}". ${young || lowUse ? 'Combined with being new or rarely used, this is the typical typosquatting pattern.' : 'Make sure this is the one you meant.'}` });

  r.risk_score = Math.min(100, findings.reduce((s, f) => s + WEIGHT[f.severity], 0));
  r.verdict = r.risk_score >= 50 ? 'high_risk' : r.risk_score >= 20 ? 'suspicious' : 'no_red_flags';
  r.advice = r.verdict === 'high_risk' ? `Do not install "${name}" until a human has verified it.${similar ? ` You may have meant "${similar}".` : ''}`
    : r.verdict === 'suspicious' ? `Verify "${name}" before installing: check the project's official docs for the exact package name and review the repository.`
    : 'No warning signs in the package metadata. This does not replace reviewing what you install.';
  return r;
}
