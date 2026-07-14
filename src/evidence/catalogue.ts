// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * Frozen secret-detection + confusable catalogue. Pure. catalogueId is derived from the canonical
 * bytes of the table, so any change to it changes the id. R12: adds secret projections (raw, NFC,
 * zero-width-stripped, confusable-skeleton) so a secret cannot hide behind Unicode confusables or
 * zero-width joiners (contract decisions 12–13). Application (omit/refuse) is the validator's job.
 */
import { canonicalBytes } from './canonical';
import { sha256Hex } from './digest';

export interface SecretPatternV1 { readonly id: string; readonly pattern: string; readonly flags: string; }

export interface SecretCatalogueV1 {
  readonly schema: string;
  readonly patterns: readonly SecretPatternV1[];
  readonly confusables: Readonly<Record<string, string>>;
  readonly zeroWidth: readonly string[];
}

export const SECRET_CATALOGUE: SecretCatalogueV1 = {
  schema: 'aukora-fu-secret-catalogue-v2',
  patterns: [
    { id: 'openrouter-key', pattern: 'sk-or-[A-Za-z0-9_\\-]{16,}', flags: 'g' },
    { id: 'openai-key', pattern: 'sk-[A-Za-z0-9]{20,}', flags: 'g' },
    { id: 'aws-access-key-id', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
    { id: 'pem-private-key', pattern: '-----BEGIN [A-Z ]*PRIVATE KEY-----', flags: 'g' },
    { id: 'jwt', pattern: 'eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{6,}', flags: 'g' },
    { id: 'env-secret-assign', pattern: '(?:API|SECRET|TOKEN|PASSWORD|PRIVATE)[A-Z0-9_]*\\s*=\\s*\\S{8,}', flags: 'gi' },
    { id: 'github-token', pattern: '(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}', flags: 'g' },
    { id: 'slack-token', pattern: 'xox[baprs]-[A-Za-z0-9-]{10,}', flags: 'g' },
    { id: 'google-api-key', pattern: 'AIza[A-Za-z0-9_\\-]{35}', flags: 'g' },
    { id: 'stripe-key', pattern: 'sk_(?:live|test)_[A-Za-z0-9]{16,}', flags: 'g' },
    { id: 'npm-token', pattern: 'npm_[A-Za-z0-9]{30,}', flags: 'g' },
    { id: 'gitlab-pat', pattern: 'glpat-[A-Za-z0-9_\\-]{16,}', flags: 'g' },
    { id: 'anthropic-key', pattern: 'sk-ant-[A-Za-z0-9_\\-]{20,}', flags: 'g' },
    { id: 'sendgrid-key', pattern: 'SG\\.[A-Za-z0-9_\\-]{16,}\\.[A-Za-z0-9_\\-]{16,}', flags: 'g' },
    { id: 'azure-account-key', pattern: 'AccountKey=[A-Za-z0-9+/]{40,}={0,2}', flags: 'g' },
    // A URL carrying userinfo credentials (scheme://user:pass@host) — the most common real leak
    // (postgres/mysql/mongodb/redis/amqp/https connection strings). Shape-based, not entropy-based,
    // so it never false-positives on legitimate high-entropy file evidence (base64, hashes, minified code).
    { id: 'url-userinfo-secret', pattern: '[a-z][a-z0-9+.\\-]*://[^\\s/:@]+:[^\\s/@]+@', flags: 'gi' },
  ],
  // Cyrillic/Greek homoglyphs → ASCII skeleton (extend deliberately; each change re-derives catalogueId).
  confusables: {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q',
    'ɡ': 'g', 'ο': 'o', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',
  },
  zeroWidth: ['​', '‌', '‍', '⁠', '﻿'],
};

export function catalogueId(): string {
  return sha256Hex(canonicalBytes(SECRET_CATALOGUE));
}

export interface SecretMatch { readonly patternId: string; readonly start: number; readonly end: number; }

export function scanForSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];
  for (const p of SECRET_CATALOGUE.patterns) {
    const flags = p.flags.indexOf('g') === -1 ? p.flags + 'g' : p.flags;
    const re = new RegExp(p.pattern, flags);
    let m: RegExpExecArray | null = re.exec(text);
    while (m !== null) {
      matches.push({ patternId: p.id, start: m.index, end: m.index + m[0].length });
      if (m[0].length === 0) re.lastIndex++;
      m = re.exec(text);
    }
  }
  matches.sort((a, b) => (a.start - b.start) || (a.end - b.end) || (a.patternId < b.patternId ? -1 : a.patternId > b.patternId ? 1 : 0));
  return matches;
}

// Strip EVERY invisible / default-ignorable / format character (not just the catalogue's core list), so a
// secret run cannot be split by e.g. U+00AD SOFT HYPHEN, bidi controls, or any other zero-width joiner
// (red-team hardening). Ordinary whitespace (TAB/LF/CR/space) is deliberately preserved.
// Also strip Unicode combining marks (\p{M}) — a secret run split by a combining mark would otherwise
// break a charset regex; stripping them rejoins the run so the scanner still catches it (red-team).
const INVISIBLE_RE = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{M}]/gu;
function stripZeroWidth(s: string): string {
  return s.replace(INVISIBLE_RE, '');
}
function confusableSkeleton(s: string): string {
  let o = '';
  for (const ch of s) o += (SECRET_CATALOGUE.confusables[ch] ?? ch);
  return o;
}

/** Defensive projections a secret might hide behind. D2 adds the COMPOSED projection
 *  confusableSkeleton(stripZeroWidth(NFC(text))) so an attacker cannot layer NFC + zero-width + confusable
 *  tricks to slip past any single-step projection (amendment 11). Round-14 red-team round 3 adds the two
 *  COMPATIBILITY projections (NFKC + composed-over-NFKC): fullwidth (U+FF01…), mathematical-alphanumeric
 *  (U+1D400…), superscript, and circled lookalikes are compatibility-equivalent to ASCII but have NO
 *  canonical (NFC) decomposition and are absent from the small confusables table, so only NFKC folds them
 *  back to ASCII where the catalogue regexes match. This closes the whole compatibility-confusable class in
 *  one step (a proven fullwidth/math-monospace bypass of a real credential). */
export function secretProjections(text: string): string[] {
  const nfc = text.normalize('NFC');
  const nfkc = text.normalize('NFKC');
  const zw = stripZeroWidth(text);
  const skeleton = confusableSkeleton(text);
  const composed = confusableSkeleton(stripZeroWidth(nfc));
  const composedK = confusableSkeleton(stripZeroWidth(nfkc));
  return [text, nfc, nfkc, zw, skeleton, composed, composedK];
}

/** True if ANY projection of `text` contains a catalogue secret (fail-closed). */
export function textHasSecret(text: string): boolean {
  for (const proj of secretProjections(text)) {
    if (scanForSecrets(proj).length > 0) return true;
  }
  return false;
}
