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

/** The four defensive projections a secret might hide behind (contract decision 12). */
export function secretProjections(text: string): string[] {
  const nfc = text.normalize('NFC');
  let zw = text;
  for (const z of SECRET_CATALOGUE.zeroWidth) zw = zw.split(z).join('');
  let skeleton = '';
  for (const ch of text) skeleton += (SECRET_CATALOGUE.confusables[ch] ?? ch);
  return [text, nfc, zw, skeleton];
}

/** True if ANY projection of `text` contains a catalogue secret (fail-closed). */
export function textHasSecret(text: string): boolean {
  for (const proj of secretProjections(text)) {
    if (scanForSecrets(proj).length > 0) return true;
  }
  return false;
}
