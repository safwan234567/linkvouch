import { parse as parseDomain } from 'tldts';
import { SG_BANK_WORDS, SG_GOV_WORDS } from '../lib/brands.ts';
import { checkLink } from './link.ts';
import type { Finding, LinkReport, Verdict } from './link.ts';

const URL_RE = /\b(?:(?:https?|hxxps?):\/\/[^\s<>"')\]]+|(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,}(?:\/[^\s<>"')\]]*)?)/gi;
const PHONE_RE = /(?:\+?\d[\d\s().-]{6,}\d)/g;

const PATTERNS: { code: string; severity: Finding['severity']; re: RegExp; detail: string }[] = [
  { code: 'urgency', severity: 'medium', re: /\b(urgent|immediately|within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|today|final (notice|reminder|warning)|last chance|expire[sd]?|suspend(ed)?|locked|deactivat\w+|act now|asap)\b/i, detail: 'Pressure to act quickly. Scammers want you rushing, not thinking.' },
  { code: 'asks_for_secrets', severity: 'high', re: /\b(otp|one[- ]time (password|pin|code)|verification code|2fa code|cvv|card (number|details)|pin( number)?|password|passcode|seed phrase|recovery phrase|nric|bank account (number|details))\b/i, detail: 'Asks for a password, OTP, card details or similar. No real bank or company asks you to share these.' },
  { code: 'threat', severity: 'medium', re: /\b(legal action|arrest|warrant|police report|court|fine[sd]?|penalt(y|ies)|blacklist(ed)?|returned to sender|will be (closed|terminated|cancelled))\b/i, detail: 'Threatens a penalty or loss if you do not respond.' },
  { code: 'too_good', severity: 'medium', re: /\b(you('ve| have) won|winner|prize|free gift|lucky draw|guaranteed (returns?|profit)|earn \$?\d+|refund of|cash ?back of|unclaimed)\b/i, detail: 'Promises money, a prize or a refund you were not expecting.' },
  { code: 'payment_request', severity: 'medium', re: /\b(pay (a |the )?(small )?(fee|customs|redelivery|shipping)|outstanding (payment|amount|bill)|top[- ]?up|gift cards?|transfer (the )?(money|funds)|crypto|bitcoin|usdt)\b/i, detail: 'Asks for a payment, fee, transfer, gift cards or crypto.' },
  { code: 'move_off_platform', severity: 'low', re: /\b(whatsapp|telegram|line|wechat) (me|us|at|on)\b|\badd me on\b/i, detail: 'Tries to move the conversation to a private chat app.' },
];

export type MessageReport = {
  verdict: Verdict; risk_score: number; findings: Finding[];
  links: LinkReport[]; phone_numbers: string[]; advice: string; limits: string;
};

export async function checkMessage(text: string): Promise<MessageReport> {
  const findings: Finding[] = [];
  const lower = text.toLowerCase();
  for (const p of PATTERNS) {
    const m = text.match(p.re);
    if (m) findings.push({ severity: p.severity, code: p.code, detail: `${p.detail} (matched: "${m[0]}")` });
  }

  const urls = [...new Set((text.match(URL_RE) ?? []).filter((c) => {
    if (/^(https?|hxxps?):/i.test(c)) return true;
    const host = c.replace(/\[\.\]/g, '.').split('/')[0];
    const p = parseDomain(host);
    return !!p.domain && p.isIcann === true;
  }))].slice(0, 5);
  const phones = [...new Set((text.match(PHONE_RE) ?? []).map((s) => s.trim()))].filter((s) => s.replace(/\D/g, '').length >= 8).slice(0, 5);

  const links = await Promise.all(urls.map((u) => checkLink(u)));

  // Singapore rules. Banks removed clickable links from SMS/email to retail customers in Jan 2022 (MAS & ABS),
  // and government SMS come from the "gov.sg" sender ID with links on .gov.sg domains.
  const bank = SG_BANK_WORDS.find((w) => new RegExp(`\\b${w}\\b`, 'i').test(lower)) ?? (/\bbank(ing)?\b/i.test(lower) ? 'bank' : undefined);
  if (bank && links.length) findings.push({ severity: 'high', code: 'sg_bank_message_with_link', detail: `Mentions a bank ("${bank}") and contains a link. Banks in Singapore do not send clickable links by SMS or email to customers (MAS/ABS measure, 2022). Elsewhere, still reach your bank through its app.` });
  const gov = SG_GOV_WORDS.find((w) => new RegExp(`\\b${w.replace('.', '\\.')}\\b`, 'i').test(lower));
  if (gov && links.some((l) => l.registrable_domain && !l.registrable_domain.endsWith('gov.sg'))) findings.push({ severity: 'high', code: 'sg_gov_message_non_gov_link', detail: `Mentions a government service ("${gov}") but links to a site that is not on .gov.sg.` });

  const worst = links.reduce((s, l) => Math.max(s, l.risk_score), 0);
  const own = findings.reduce((s, f) => s + ({ high: 50, medium: 20, low: 8, info: 0 }[f.severity]), 0);
  const score = Math.min(100, Math.max(worst, own) + (worst && own ? 10 : 0));
  const verdict: Verdict = score >= 50 ? 'high_risk' : score >= 20 ? 'suspicious' : 'no_red_flags';
  const advice = verdict === 'high_risk' ? 'This looks like a scam. Do not tap the link, reply, or call the number in the message. Contact the organisation through its official app or the number on its official website. In Singapore you can check or report it with ScamShield (call 1799).'
    : verdict === 'suspicious' ? 'Some warning signs. Do not use links or numbers from the message; verify through the official app or website.'
    : 'No obvious scam patterns found, but stay cautious with unexpected messages.';
  return { verdict, risk_score: score, findings, links, phone_numbers: phones, advice,
    limits: 'Pattern-based check of the text plus link checks. It cannot confirm who really sent the message. Phone numbers are listed but not verified.' };
}
