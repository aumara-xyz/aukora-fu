// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/** Hostile matrix + known-answer vectors for the pure EvidencePack v1 (Round-12 immune gate). No I/O. */
import { describe, it, expect } from 'vitest';
import {
  EVIDENCE_PACK_SCHEMA, EvidencePackV1, EvidenceFileV1, EvidenceTestRunV1,
  canonicalString, canonicalBytes, verifyCanonicalWire,
  packDigest, sha256Hex, uint64BE,
  deriveFenceNonce, fenceOpen, fenceCollisionFree,
  SECRET_CATALOGUE, catalogueId, scanForSecrets, textHasSecret,
  validatePackBody, validateEnvelope, sealEnvelope, verifyEnvelope, renderForSeat,
} from '../src/evidence/index';

// ── Pinned known-answer vectors (contract decision 11; reproduced by scripts/pyref + Node + Bun) ──
const KAT_CATALOGUE_ID = '04b0ae213e8dacb99665015bbc761e9cddef68391902ef0026af13dda82a94cb';
const KAT_CANON = '{"advisoryOnly":true,"baseCommit":null,"baseTree":null,"builderToolVersions":{"node":"v22.23.0"},"catalogueId":"04b0ae213e8dacb99665015bbc761e9cddef68391902ef0026af13dda82a94cb","files":[],"grantsAuthority":false,"headCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headTree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","limitsProfileId":"default-v1","omissions":[],"repoId":"aumara-xyz/aukora-fu","rootAllowlist":[],"schema":"aukora-fu-evidence-pack-v1","testRuns":[]}';
const KAT_MIN_DIGEST = '508d43495fcd40dfde386893069848251b82974a395f329bbe8e8696d764a878';
const KAT_MAX_DIGEST = '6e8f436fa6266400d7816970e904251673c8ad9f0d1e0b8eb8d9c5e2ad99f2aa';
const KAT_FENCE = '3a23cb4c6895e0ca934a95f328985122';
const SHA_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
const SHA_ZEROS3 = '709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c';

const enc = new TextEncoder();
const NUL = String.fromCharCode(0);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

function mkTextFile(path: string, content: string): EvidenceFileV1 {
  const bytes = enc.encode(content); const h = sha256Hex(bytes);
  return { path, kind: 'text', originalSizeBytes: bytes.length, includedByteStart: 0, includedByteEnd: bytes.length, truncated: false, fullSha256: h, includedSha256: h, encoding: 'utf8', content };
}
function mkTest(command: string[], cwdRelative = '.'): EvidenceTestRunV1 {
  return { command, cwdRelative, exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 0, stderrBytes: 0, stdoutExcerpt: '', stderrExcerpt: '', durationMs: null, toolVersions: {} };
}
function bodyWith(files: EvidenceFileV1[], omissions: EvidencePackV1['omissions'], testRuns: EvidenceTestRunV1[]): EvidencePackV1 {
  const allow = [...files.map((f) => f.path), ...omissions.map((o) => o.path)].sort();
  return {
    schema: EVIDENCE_PACK_SCHEMA, advisoryOnly: true, grantsAuthority: false, repoId: 'aumara-xyz/aukora-fu',
    headCommit: 'a'.repeat(40), headTree: 'b'.repeat(40), baseCommit: null, baseTree: null,
    files, omissions, testRuns, rootAllowlist: allow, limitsProfileId: 'default-v1',
    builderToolVersions: { node: 'v22.23.0' }, catalogueId: catalogueId(),
  };
}
function minimalBody(): EvidencePackV1 { return bodyWith([], [], []); }
function maximalBody(): EvidencePackV1 {
  const a: EvidenceFileV1 = { path: 'a.ts', kind: 'text', originalSizeBytes: 5, includedByteStart: 0, includedByteEnd: 5, truncated: false, fullSha256: SHA_HELLO, includedSha256: SHA_HELLO, encoding: 'utf8', content: 'hello' };
  const b: EvidenceFileV1 = { path: 'b.png', kind: 'binary', originalSizeBytes: 3, includedByteStart: 0, includedByteEnd: 3, truncated: false, fullSha256: SHA_ZEROS3, includedSha256: SHA_ZEROS3, encoding: 'base64', content: 'AAAA' };
  return bodyWith([a, b], [{ path: 'secret.env', reason: 'secret-file', originalSizeBytes: null, sha256: null }], [mkTest(['npm', 'run', 'verify'])]);
}

describe('known-answer vectors', () => {
  it('match pinned values (also reproduced by scripts/pyref/evidence_canonical_ref.py)', () => {
    expect(catalogueId()).toBe(KAT_CATALOGUE_ID);
    expect(canonicalString(minimalBody())).toBe(KAT_CANON);
    expect(packDigest(minimalBody())).toBe(KAT_MIN_DIGEST);
    expect(packDigest(maximalBody())).toBe(KAT_MAX_DIGEST);
    expect(deriveFenceNonce('00'.repeat(32), ['hello', 'world'])).toBe(KAT_FENCE);
    expect(canonicalBytes(maximalBody()).indexOf(0)).toBe(-1);
  });
  it('accepts minimal + maximal', () => {
    expect(validatePackBody(minimalBody()).ok).toBe(true);
    expect(validatePackBody(maximalBody()).ok).toBe(true);
  });
});

describe('decision 14: canonicalizer rejects -0', () => {
  it('-0 throws; 0 is fine; body -0 fails', () => {
    expect(() => canonicalString(-0)).toThrow();
    expect(canonicalString(0)).toBe('0');
    const m = maximalBody(); (m.testRuns[0] as any).exitCode = -0; expect((validatePackBody(m) as any).code).toBe('E_BAD_INTEGER');
  });
});

describe('decision 15: strict canonical-wire verification', () => {
  it('accepts canonical; rejects BOM / whitespace / dup keys / alt-number / alt-escape', () => {
    expect(verifyCanonicalWire(KAT_CANON)).toBe(true);
    expect(verifyCanonicalWire('﻿' + KAT_CANON)).toBe(false);
    expect(verifyCanonicalWire(' ' + KAT_CANON)).toBe(false);
    expect(verifyCanonicalWire('{"a":1,"a":2}')).toBe(false);
    expect(verifyCanonicalWire('{"a":1.0}')).toBe(false);
    expect(verifyCanonicalWire('{ "a":1}')).toBe(false);
    expect(verifyCanonicalWire('{"a":"\\u0041"}')).toBe(false);
  });
});

describe('decisions 1-3: full vs included hashes; complete equality', () => {
  it('recomputes includedSha256 and rejects a mismatch', () => {
    const m = maximalBody(); (m.files[0] as any).includedSha256 = '0'.repeat(64);
    expect((validatePackBody(m) as any).code).toBe('E_HASH_INCLUDED');
  });
  it('a complete file must have includedSha256 === fullSha256', () => {
    const m = maximalBody(); (m.files[0] as any).fullSha256 = 'a'.repeat(64);
    expect((validatePackBody(m) as any).code).toBe('E_HASH_COMPLETE');
  });
});

describe('decisions 4-5: no omitted encoding; canonical base64', () => {
  it('rejects encoding "omitted" and non-canonical base64', () => {
    const m = maximalBody(); (m.files[0] as any).encoding = 'omitted'; expect((validatePackBody(m) as any).code).toBe('E_BAD_ENUM');
    const b = maximalBody(); (b.files[1] as any).content = 'AAA';
    expect(['E_BASE64_NONCANONICAL', 'E_CONTENT_LENGTH', 'E_HASH_INCLUDED']).toContain((validatePackBody(b) as any).code);
  });
});

describe('decision 6: exact files/omissions/allowlist partition', () => {
  it('rejects a missing or extra allowlist path and an overlap', () => {
    const miss = maximalBody(); (miss as any).rootAllowlist = ['a.ts', 'b.png']; expect((validatePackBody(miss) as any).code).toBe('E_PARTITION');
    const extra = maximalBody(); (extra as any).rootAllowlist = ['a.ts', 'b.png', 'secret.env', 'zzz.ts']; expect((validatePackBody(extra) as any).code).toBe('E_PARTITION');
    const overlap = maximalBody(); (overlap.omissions[0] as any).path = 'a.ts'; (overlap as any).rootAllowlist = ['a.ts', 'b.png']; expect((validatePackBody(overlap) as any).code).toBe('E_PARTITION');
  });
});

describe('decisions 7-9: paths + open maps', () => {
  it('rejects absolute/traversal file paths and bad cwd', () => {
    for (const bad of ['/etc/x', '../x', 'a\\b']) { const m = bodyWith([mkTextFile(bad, 'x')], [], []); expect((validatePackBody(m) as any).code).toBe('E_REL_PATH'); }
    const cwd = maximalBody(); (cwd.testRuns[0] as any).cwdRelative = '/abs'; expect((validatePackBody(cwd) as any).code).toBe('E_CWD');
  });
  it('rejects raw NUL, non-ASCII map key, non-NFC map value', () => {
    const nul = clone(minimalBody()); (nul as any).repoId = 'x' + NUL; expect((validatePackBody(nul) as any).code).toBe('E_NUL');
    const key = maximalBody(); (key.builderToolVersions as any)['bad key'] = 'x'; expect((validatePackBody(key) as any).code).toBe('E_MAP_KEY');
    const val = maximalBody(); (val.builderToolVersions as any).tool = 'café'; expect((validatePackBody(val) as any).code).toBe('E_MAP_VALUE_NFC');
  });
});

describe('decisions 10-11: UTF-8-framed test identity', () => {
  it('["a","b"] != ["a b"]; duplicate identities rejected', () => {
    const ok = bodyWith([], [], [mkTest(['a', 'b']), mkTest(['a b'])]);
    const r = validatePackBody(ok);
    expect(r.ok || (r as any).code === 'E_ARRAY_UNSORTED').toBe(true);
    const dup = bodyWith([], [], [mkTest(['x']), mkTest(['x'])]);
    expect((validatePackBody(dup) as any).code).toBe('E_DUP_TEST');
  });
});

describe('decisions 12-13: projection secret refusal', () => {
  it('detects secrets across raw / base64 / confusable projections', () => {
    expect(textHasSecret('key=sk-or-abcdefghijklmnop0123')).toBe(true);
    expect(textHasSecret('sk-оr-abcdefghijklmnop0123')).toBe(true); // Cyrillic о skeleton
    const raw = 'sk-or-abcdefghijklmnop0123';
    const bytes = new Uint8Array(Buffer.from(raw)); const b64 = Buffer.from(raw).toString('base64'); const h = sha256Hex(bytes);
    const m = bodyWith([{ path: 'k.bin', kind: 'binary', originalSizeBytes: bytes.length, includedByteStart: 0, includedByteEnd: bytes.length, truncated: false, fullSha256: h, includedSha256: h, encoding: 'base64', content: b64 }], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('refuses a secret in a test excerpt; no prose false-positive', () => {
    const m = maximalBody(); (m.testRuns[0] as any).stdoutExcerpt = 'sk-or-abcdefghijklmnop0123';
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
    expect(scanForSecrets('discusses tokens and signatures').length).toBe(0);
  });
});

describe('authority + envelope + seat render', () => {
  it('rejects authority-shaped keys; not content', () => {
    const m = maximalBody(); (m.builderToolVersions as any).signature = 'x'; expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
    const ok = bodyWith([mkTextFile('a.ts', 'sign grant token apply seed')], [], []);
    expect(validatePackBody(ok).ok).toBe(true);
  });
  it('seals {body, packDigest}, verifies, rejects tamper; renders identically per seat', () => {
    const env = sealEnvelope(maximalBody());
    expect(Object.keys(env).sort()).toEqual(['body', 'packDigest']);
    expect(verifyEnvelope(env)).toBe(true);
    const bad = { ...env, packDigest: env.packDigest.slice(0, 63) + (env.packDigest[63] === 'a' ? 'b' : 'a') };
    expect((validateEnvelope(bad) as any).code).toBe('E_DIGEST_MISMATCH');
    expect(Buffer.from(renderForSeat(env, 'A')).equals(Buffer.from(renderForSeat(env, 'B')))).toBe(true);
    expect(Array.from(uint64BE(4294967296))).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
    expect(fenceCollisionFree(deriveFenceNonce(env.packDigest, ['x']), ['x'])).toBe(true);
    void SECRET_CATALOGUE; void fenceOpen;
  });
});
