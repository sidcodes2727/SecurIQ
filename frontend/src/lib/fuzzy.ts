/**
 * Small fuzzy matcher for the command palette: every query character must appear in order.
 * Scores reward consecutive runs, word starts and a match at the very beginning.
 */
export interface FuzzyResult { score: number; indices: number[] }

const BOUNDARY = /[\s\-_./:·()]/;

export function fuzzy(query: string, text: string): FuzzyResult | null {
  // separators are interchangeable ("weak ikev1" finds "weak_ikev1"); replacements keep indices aligned
  const sep = (s: string) => s.toLowerCase().replace(/[_\-./]/g, ' ');
  const q = sep(query).replace(/\s+/g, '');
  if (!q) return { score: 0, indices: [] };
  const t = sep(text);
  const phrase = sep(query).trim().replace(/\s+/g, ' ');
  // fast path: a plain substring beats any scattered match
  const at = t.indexOf(phrase);
  if (at >= 0 && phrase) {
    const len = phrase.length;
    return { score: 100 + (at === 0 ? 40 : BOUNDARY.test(t[at - 1] ?? ' ') ? 20 : 0) - at * 0.5 + len,
      indices: Array.from({ length: len }, (_, i) => at + i) };
  }
  const indices: number[] = [];
  let score = 0, ti = 0, run = 0;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found < 0) return null;
    const boundary = found === 0 || BOUNDARY.test(t[found - 1]);
    run = indices.length && found === indices[indices.length - 1] + 1 ? run + 1 : 0;
    score += 1 + run * 3 + (boundary ? 6 : 0) - Math.min(found - ti, 8) * 0.4;
    indices.push(found);
    ti = found + 1;
  }
  return { score, indices };
}

/** Split text into highlighted / plain segments for rendering. */
export function highlight(text: string, indices: number[]): { text: string; hit: boolean }[] {
  if (!indices.length) return [{ text, hit: false }];
  const set = new Set(indices);
  const out: { text: string; hit: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const hit = set.has(i);
    const last = out[out.length - 1];
    if (last && last.hit === hit) last.text += text[i];
    else out.push({ text: text[i], hit });
  }
  return out;
}
