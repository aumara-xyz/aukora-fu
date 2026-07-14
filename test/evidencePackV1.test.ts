// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/** Hostile test matrix for the pure EvidencePack v1 (docs/EVIDENCEPACK_V1.md). No I/O. */
import { describe, it, expect } from 'vitest';
import {
  EVIDENCE_PACK_SCHEMA, EvidencePackV1,
  canonicalString, canonicalBytes,
  packDigest, sha256Hex, uint64BE,
  deriveFenceNonce, fence, fenceOpen, fenceClose, fenceCollisionFree,
  SECRET_CATALOGUE, catalogueId, scanForSecrets,
  validatePackBody, validateEnvelope, sealEnvelope, verifyEnvelope, renderForSeat,
} from '../src/evidence/index';

function minimalBody(): EvidencePackV1 {
  return {
    schema: EVIDENCE_PACK_SCHEMA, advisoryOnly: true, grantsAuthority: false,
    repo: 'aumara-xyz/aukora-fu',
    baseCommit: 'a'.repeat(40), headCommit: 'b'.repeat(40), headTree: 'c'.repeat(40),
    createdAtIso: '2026-07-14T00:00:00Z', diffSha256: 'd'.repeat(64),
    files: [], omissions: [], tests: [], claims: [], rootAllowlist: [],
    limits: { maxFileBytes: 1048576, maxPackBytes: 8388608, maxFiles: 4096 },
    builderToolVersions: { node: 'v22.23.0' }, dataFenceNonce: 'e'.repeat(32),
  };
}
function maximalBody(): EvidencePackV1 {
  return {
    ...minimalBody(),
    files: [
      { path: 'a.ts', kind: 'text', originalSizeBytes: 10, includedByteStart: 0, includedByteEnd: 10, truncated: false, sha256: '1'.repeat(64), encoding: 'utf8', content: 'hello', secretsRedacted: 0 },
      { path: 'b.png', kind: 'binary', originalSizeBytes: 4, includedByteStart: 0, includedByteEnd: 4, truncated: false, sha256: '2'.repeat(64), encoding: 'base64', content: 'AAAA', secretsRedacted: 0 },
    ],
    omissions: [{ path: 'secret.env', reason: 'E_SECRET_FILE', originalSizeBytes: null, sha256: null }],
    tests: [{ command: ['npm', 'run', 'verify'], cwdRelative: '.', exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 5, stderrBytes: 0, stdoutExcerpt: 'ok', durationMs: 12, toolVersions: { node: 'v22.23.0' } }],
    claims: [{ id: 'c1', text: 'this file discusses signature, token, and grant safely' }],
    rootAllowlist: ['a.ts', 'b.png'],
  };
}
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

describe('canonical serialization', () => {
  it('is insensitive to object key insertion order', () => {
    const a = { b: 1, a: 2, c: [3, { z: 9, y: 8 }] };
    const b = { c: [3, { y: 8, z: 9 }], a: 2, b: 1 };
    expect(canonicalString(a)).toBe(canonicalString(b));
  });
  it('preserves array order', () => {
    expect(canonicalString([3, 1, 2])).toBe('[3,1,2]');
  });
  it('rejects non-safe / non-finite / float numbers', () => {
    expect(() => canonicalString(1.5)).toThrow();
    expect(() => canonicalString(Number.MAX_SAFE_INTEGER + 1)).toThrow();
    expect(() => canonicalString(Infinity)).toThrow();
    expect(() => canonicalString(NaN)).toThrow();
  });
  it('normalizes -0 to 0', () => {
    expect(canonicalString(-0)).toBe('0');
  });
});

describe('digest: domain-separated, length-framed', () => {
  it('is deterministic and reproducible', () => {
    expect(packDigest(minimalBody())).toBe(packDigest(clone(minimalBody())));
  });
  it('every single-leaf mutation changes the digest', () => {
    const base = packDigest(minimalBody());
    const m1 = clone(minimalBody()); (m1 as any).repo = 'x'; expect(packDigest(m1)).not.toBe(base);
    const m2 = clone(minimalBody()); (m2 as any).createdAtIso = '2026-07-14T00:00:01Z'; expect(packDigest(m2)).not.toBe(base);
    const m3 = clone(minimalBody()); (m3 as any).dataFenceNonce = 'f'.repeat(32); expect(packDigest(m3)).not.toBe(base);
  });
  it('length framing separates otherwise-ambiguous concatenations', () => {
    // Two distinct bodies whose canonical bytes differ only by a boundary must not collide.
    const a = clone(minimalBody()); (a as any).repo = 'ab'; (a as any).headTree = 'c'.repeat(40);
    const b = clone(minimalBody()); (b as any).repo = 'a'; (b as any).headTree = 'c'.repeat(40);
    expect(packDigest(a)).not.toBe(packDigest(b));
  });
  it('uint64BE encodes big values without 32-bit overflow', () => {
    expect(Array.from(uint64BE(256))).toEqual([0, 0, 0, 0, 0, 0, 1, 0]);
    expect(Array.from(uint64BE(4294967296))).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
  });
});

describe('validator: structural', () => {
  it('accepts minimal and maximal valid bodies', () => {
    expect(validatePackBody(minimalBody()).ok).toBe(true);
    expect(validatePackBody(maximalBody()).ok).toBe(true);
  });
  it('rejects unknown top-level field', () => {
    const m = clone(minimalBody()); (m as any).evil = 1;
    const r = validatePackBody(m); expect(r.ok).toBe(false); expect((r as any).code).toBe('E_UNKNOWN_FIELD');
  });
  it('rejects unknown field nested inside a file', () => {
    const m = maximalBody(); (m.files[0] as any).evil = 1;
    expect((validatePackBody(m) as any).code).toBe('E_UNKNOWN_FIELD');
  });
  it('rejects missing field', () => {
    const m = clone(minimalBody()); delete (m as any).repo;
    expect((validatePackBody(m) as any).code).toBe('E_MISSING_FIELD');
  });
  it('rejects wrong-typed field', () => {
    const m = clone(minimalBody()); (m as any).repo = 5;
    expect((validatePackBody(m) as any).code).toBe('E_WRONG_TYPE');
  });
});

describe('validator: advisory literals', () => {
  it('rejects advisoryOnly false', () => {
    const m = clone(minimalBody()); (m as any).advisoryOnly = false;
    expect((validatePackBody(m) as any).code).toBe('E_ADVISORY_LITERAL');
  });
  it('rejects grantsAuthority true', () => {
    const m = clone(minimalBody()); (m as any).grantsAuthority = true;
    expect((validatePackBody(m) as any).code).toBe('E_ADVISORY_LITERAL');
  });
});

describe('validator: authority-shaped keys (open maps only)', () => {
  it('rejects an authority-shaped key in toolVersions', () => {
    const m = maximalBody(); (m.tests[0].toolVersions as any).signature = 'x';
    expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
  });
  it('rejects an authority-shaped key in builderToolVersions', () => {
    const m = clone(minimalBody()); (m.builderToolVersions as any).apply_token = 'x';
    expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
  });
  it('does NOT flag content that merely discusses signatures/tokens/grants', () => {
    const m = maximalBody();
    (m.files[0] as any).content = 'const signature = grant(token, apply, seed);';
    expect(validatePackBody(m).ok).toBe(true);
  });
  it('does NOT flag the legitimate grantsAuthority field name', () => {
    expect(validatePackBody(minimalBody()).ok).toBe(true);
  });
});

describe('validator: unicode / hex / timestamps', () => {
  it('rejects a non-NFC path', () => {
    const m = maximalBody(); (m.files[0] as any).path = 'café.ts'; // NFD
    expect((validatePackBody(m) as any).code).toBe('E_NOT_NFC');
  });
  it('rejects a lone surrogate in a string', () => {
    const m = clone(minimalBody()); (m as any).repo = 'x' + String.fromCharCode(0xD800);
    expect((validatePackBody(m) as any).code).toBe('E_INVALID_UTF8');
  });
  it('rejects uppercase / short / long sha256', () => {
    for (const bad of ['D'.repeat(64), 'd'.repeat(63), 'd'.repeat(65)]) {
      const m = clone(minimalBody()); (m as any).diffSha256 = bad;
      expect((validatePackBody(m) as any).code).toBe('E_BAD_SHA');
    }
  });
  it('rejects a 41-hex git sha', () => {
    const m = clone(minimalBody()); (m as any).baseCommit = 'a'.repeat(41);
    expect((validatePackBody(m) as any).code).toBe('E_BAD_GITSHA');
  });
  it('rejects a non-ISO timestamp', () => {
    const m = clone(minimalBody()); (m as any).createdAtIso = '2026-07-14 00:00:00';
    expect((validatePackBody(m) as any).code).toBe('E_BAD_TIMESTAMP');
  });
});

describe('validator: numbers', () => {
  it('rejects float, unsafe, negative, and -0 integer fields', () => {
    for (const bad of [1.5, Number.MAX_SAFE_INTEGER + 2, -1, -0]) {
      const m = clone(maximalBody()); (m.files[0] as any).originalSizeBytes = bad; (m.files[0] as any).includedByteEnd = 0;
      expect((validatePackBody(m) as any).code).toBe('E_BAD_INTEGER');
    }
  });
  it('allows a negative exitCode but rejects -0', () => {
    const m = clone(maximalBody()); (m.tests[0] as any).exitCode = -9;
    expect(validatePackBody(m).ok).toBe(true);
    const m2 = clone(maximalBody()); (m2.tests[0] as any).exitCode = -0;
    expect((validatePackBody(m2) as any).code).toBe('E_BAD_INTEGER');
  });
});

describe('validator: ordering / duplicates / ranges', () => {
  it('rejects unsorted files', () => {
    const m = maximalBody(); const tmp = m.files[0]; (m as any).files = [m.files[1], tmp];
    expect((validatePackBody(m) as any).code).toBe('E_ARRAY_UNSORTED');
  });
  it('rejects a path present in both files and omissions', () => {
    const m = maximalBody(); (m.omissions[0] as any).path = 'a.ts';
    expect((validatePackBody(m) as any).code).toBe('E_DUP_PATH');
  });
  it('rejects an inconsistent truncated flag', () => {
    const m = maximalBody(); (m.files[0] as any).includedByteEnd = 5; (m.files[0] as any).truncated = false;
    expect((validatePackBody(m) as any).code).toBe('E_BAD_RANGE');
  });
  it('rejects a binary file inlined as utf8', () => {
    const m = maximalBody(); (m.files[1] as any).encoding = 'utf8';
    expect((validatePackBody(m) as any).code).toBe('E_BINARY_INLINE');
  });
});

describe('digest-echo / envelope / seat render', () => {
  it('seals and verifies a valid envelope', () => {
    const env = sealEnvelope(minimalBody());
    expect(verifyEnvelope(env)).toBe(true);
    expect(validateEnvelope(env).ok).toBe(true);
  });
  it('rejects a tampered digest (one byte)', () => {
    const env = sealEnvelope(minimalBody());
    const bad = { body: env.body, packDigest: env.packDigest.slice(0, 63) + (env.packDigest[63] === 'a' ? 'b' : 'a') };
    expect(verifyEnvelope(bad as any)).toBe(false);
    expect((validateEnvelope(bad) as any).code).toBe('E_DIGEST_MISMATCH');
  });
  it('rejects a decoy digest of a different body', () => {
    const env = sealEnvelope(minimalBody());
    const bad = { body: env.body, packDigest: packDigest(maximalBody()) };
    expect((validateEnvelope(bad) as any).code).toBe('E_DIGEST_MISMATCH');
  });
  it('rejects an unknown field on the envelope', () => {
    const env = sealEnvelope(minimalBody());
    expect((validateEnvelope({ ...env, extra: 1 }) as any).code).toBe('E_UNKNOWN_FIELD');
  });
  it('renders byte-identically for every seat', () => {
    const env = sealEnvelope(maximalBody());
    const a = renderForSeat(env, 'seat-A');
    const b = renderForSeat(env, 'seat-B');
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    // one-byte divergence would be detectable:
    expect(Buffer.from(a).equals(Buffer.from(canonicalBytes(env)))).toBe(true);
  });
});

describe('framing (pure)', () => {
  it('derives a nonce whose fence tokens do not occur in the content', () => {
    const contents = ['hello', 'world ⟪DATA:deadbeef⟫'];
    const nonce = deriveFenceNonce(contents);
    expect(fenceCollisionFree(nonce, contents)).toBe(true);
    const wrapped = fence(nonce, 'x');
    expect(wrapped.startsWith(fenceOpen(nonce))).toBe(true);
    expect(wrapped.endsWith(fenceClose(nonce))).toBe(true);
  });
});

describe('catalogue (pure, derived identity)', () => {
  it('has a stable derived catalogueId', () => {
    expect(catalogueId()).toBe(catalogueId());
    expect(catalogueId()).toMatch(/^[0-9a-f]{64}$/);
  });
  it('changing the catalogue changes catalogueId', () => {
    const mutated = { ...SECRET_CATALOGUE, patterns: [...SECRET_CATALOGUE.patterns, { id: 'x', pattern: 'z', flags: 'g' }] };
    expect(sha256Hex(canonicalBytes(mutated))).not.toBe(catalogueId());
  });
  it('detects a secret token in content', () => {
    const m = scanForSecrets('key=sk-or-abcdefghijklmnop0123 done');
    expect(m.length).toBeGreaterThan(0);
  });
  it('does not false-positive on ordinary prose', () => {
    expect(scanForSecrets('this discusses tokens and signatures in prose').length).toBe(0);
  });
});
