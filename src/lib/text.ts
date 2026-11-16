// String helpers: edit distance and "skeletons" that undo look-alike tricks.

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

// Characters from other alphabets that look like Latin letters.
const CONFUSABLES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h',
  'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'к': 'k', 'м': 'm', 'т': 't', 'в': 'b', 'н': 'h', 'ԛ': 'q', 'ԝ': 'w',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'đ': 'd', 'ß': 'b',
};
const LEET: Record<string, string> = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b' };

/** Map look-alike characters to plain Latin: "pаypa1" -> "paypal". */
export function skeleton(s: string): string {
  let out = '';
  for (const ch of s.toLowerCase().normalize('NFKD')) {
    if (/\p{M}/u.test(ch)) continue; // accents
    out += CONFUSABLES[ch] ?? LEET[ch] ?? ch;
  }
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
}

export const hasNonAscii = (s: string) => /[^\x00-\x7f]/.test(s);

/** True when b is a with two neighbouring letters swapped ("reqeusts" vs "requests"). */
export function isAdjacentSwap(a: string, b: string): boolean {
  if (a.length !== b.length || a === b) return false;
  const i = [...a].findIndex((ch, k) => ch !== b[k]);
  return i >= 0 && i < a.length - 1 && a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
}
