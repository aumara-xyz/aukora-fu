// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * Frozen secret-detection + confusable catalogue (docs/EVIDENCEPACK_V1.md §11). Pure. catalogueId is
 * derived from the canonical bytes of the table, so any change to it changes the id. Commit 1 owns the
 * catalogue + the matcher; the omit/redact/abort application belongs to the Commit-2 filesystem reader.
 */
import { canonicalBytes } from './canonical';
import { sha256Hex } from './digest';

export interface SecretPatternV1 { readonly id: string; readonly pattern: string; readonly flags: string; }

export interface SecretCatalogueV1 {
  readonly schema: string;
  readonly patterns: readonly SecretPatternV1[];
  readonly confusables: Readonly<Record<string, string>>;
}

export const SECRET_CATALOGUE: SecretCatalogueV1 = {
  schema: 'aukora-fu-secret-catalogue-v1',
  patterns: [
    { id: 'openrouter-key', pattern: 'sk-or-[A-Za-z0-9_\\-]{16,}', flags: 'g' },
    { id: 'openai-key', pattern: 'sk-[A-Za-z0-9]{20,}', flags: 'g' },
    { id: 'aws-access-key-id', pattern: 'AKIA[0-9A-Z]{16}', flags: 'g' },
    { id: 'pem-private-key', pattern: '-----BEGIN [A-Z ]*PRIVATE KEY-----', flags: 'g' },
    { id: 'jwt', pattern: 'eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{6,}', flags: 'g' },
    { id: 'env-secret-assign', pattern: '(?:API|SECRET|TOKEN|PASSWORD|PRIVATE)[A-Z0-9_]*\\s*=\\s*\\S{8,}', flags: 'gi' },
  ],
  confusables: {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  },
};

export function catalogueId(): string {
  return sha256Hex(canonicalBytes(SECRET_CATALOGUE));
}

export interface SecretMatch { readonly patternId: string; readonly start: number; readonly end: number; }

/** Pure content scanner. Never applied to object KEYS (authority screening handles keys); only to
 *  free-text content the caller chooses to scan. */
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
