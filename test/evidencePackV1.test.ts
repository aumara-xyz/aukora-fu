// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/** Hostile test matrix + known-answer vectors for the pure EvidencePack v1 (Round-11 settled contract). No I/O. */
import { describe, it, expect } from 'vitest';
import {
  EVIDENCE_PACK_SCHEMA, EvidencePackV1,
  canonicalString, canonicalBytes,
  packDigest, sha256Hex, uint64BE,
  deriveFenceNonce, fenceOpen, fenceClose, fenceCollisionFree,
  SECRET_CATALOGUE, catalogueId, scanForSecrets,
  validatePackBody, validateEnvelope, sealEnvelope, verifyEnvelope, renderForSeat,
} from '../src/evidence/index';

// ── Independently pinned known-answer vectors (contract decision 11) ──────────────────────────────
const KAT_CATALOGUE_ID = '84c3e084aeee5ea8cf86e86e9262a53625758f85a9d3aa1d4051388c08f7ed92';
const KAT_CANON = '{"advisoryOnly":true,"baseCommit":null,"baseTree":null,"builderToolVersions":{"node":"v22.23.0"},"catalogueId":"84c3e084aeee5ea8cf86e86e9262a53625758f85a9d3aa1d4051388c08f7ed92","files":[],"grantsAuthority":false,"headCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headTree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","limitsProfileId":"default-v1","omissions":[],"repoId":"aumara-xyz/aukora-fu","rootAllowlist":[],"schema":"aukora-fu-evidence-pack-v1","testRuns":[]}';
const KAT_PACK_DIGEST = '026c6f843dd8e428d1dc22d227222fd7689a7cb7dd8494a5e761fb1161d9da29';
const KAT_FENCE = '3a23cb4c6895e0ca934a95f328985122';

function freshBase(): Omit<EvidencePackV1, 'catalogueId'> {
  return {
    schema: EVIDENCE_PACK_SCHEMA, advisoryOnly: true as const, grantsAuthority: false as const,
    repoId: 'aumara-xyz/aukora-fu', headCommit: 'a'.repeat(40), headTree: 'b'.repeat(40),
    baseCommit: null, baseTree: null, files: [], omissions: [], testRuns: [], rootAllowlist: [],
    limitsProfileId: 'default-v1', builderToolVersions: { node: 'v22.23.0' },
  };
}
function minimalBody(): EvidencePackV1 { return { ...freshBase(), catalogueId: catalogueId() }; }
function maximalBody(): EvidencePackV1 {
  return {
    ...freshBase(),
    files: [
      { path: 'a.ts', kind: 'text', originalSizeBytes: 5, includedByteStart: 0, includedByteEnd: 5, truncated: false, sha256: '1'.repeat(64), encoding: 'utf8', content: 'hello' },
      { path: 'b.png', kind: 'binary', originalSizeBytes: 3, includedByteStart: 0, includedByteEnd: 3, truncated: false, sha256: '2'.repeat(64), encoding: 'base64', content: 'AAAA' },
    ],
    omissions: [{ path: 'secret.env', reason: 'secret-file', originalSizeBytes: null, sha256: null }],
    testRuns: [{ command: ['npm', 'run', 'verify'], cwdRelative: '.', exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 5, stderrBytes: 0, stdoutExcerpt: 'ok', durationMs: 12, toolVersions: { node: 'v22.23.0' } }],
    rootAllowlist: ['a.ts', 'b.png'],
    catalogueId: catalogueId(),
  };
}
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const NUL = '\u0000';

describe('known-answer vectors (independently recomputable)', () => {
  it('catalogueId / canonical bytes / packDigest / fence match pinned KATs', () => {
    expect(catalogueId()).toBe(KAT_CATALOGUE_ID);
    expect(canonicalString(minimalBody())).toBe(KAT_CANON);
    expect(packDigest(minimalBody())).toBe(KAT_PACK_DIGEST);
    expect(deriveFenceNonce('00'.repeat(32), ['hello', 'world'])).toBe(KAT_FENCE);
  });
  it('canonical bytes contain no NUL', () => {
    expect(canonicalBytes(maximalBody()).indexOf(0)).toBe(-1);
  });
});

describe('canonical + digest', () => {
  it('key-insertion-order invariant; arrays preserved; -0 normalized; unsafe rejected', () => {
    expect(canonicalString({ b: 1, a: 2 })).toBe(canonicalString({ a: 2, b: 1 }));
    expect(canonicalString([3, 1, 2])).toBe('[3,1,2]');
    expect(canonicalString(-0)).toBe('0');
    expect(() => canonicalString(1.5)).toThrow();
  });
  it('length framing + leaf mutation change the digest', () => {
    const b0 = packDigest(minimalBody());
    const m = clone(minimalBody()); (m as any).repoId = 'x'; expect(packDigest(m)).not.toBe(b0);
    expect(Array.from(uint64BE(4294967296))).toEqual([0, 0, 0, 1, 0, 0, 0, 0]);
  });
});

describe('validator: structure / literals / unknown+authority keys', () => {
  it('accepts minimal + maximal', () => {
    expect(validatePackBody(minimalBody()).ok).toBe(true);
    expect(validatePackBody(maximalBody()).ok).toBe(true);
  });
  it('rejects unknown fields (incl. a self-declared limits object)', () => {
    const m = clone(minimalBody()); (m as any).evil = 1; expect((validatePackBody(m) as any).code).toBe('E_UNKNOWN_FIELD');
    const m2 = clone(minimalBody()); (m2 as any).limits = { maxFiles: 999999 }; expect((validatePackBody(m2) as any).code).toBe('E_UNKNOWN_FIELD');
  });
  it('rejects advisory-literal violations and stray timestamp/claims', () => {
    const m = clone(minimalBody()); (m as any).advisoryOnly = false; expect((validatePackBody(m) as any).code).toBe('E_ADVISORY_LITERAL');
    const m2 = clone(minimalBody()); (m2 as any).grantsAuthority = true; expect((validatePackBody(m2) as any).code).toBe('E_ADVISORY_LITERAL');
    const m3 = clone(minimalBody()); (m3 as any).createdAtIso = '2026-07-14T00:00:00Z'; expect((validatePackBody(m3) as any).code).toBe('E_UNKNOWN_FIELD');
    const m4 = clone(minimalBody()); (m4 as any).claims = []; expect((validatePackBody(m4) as any).code).toBe('E_UNKNOWN_FIELD');
    const m5 = clone(minimalBody()); (m5 as any).diffSha256 = 'd'.repeat(64); expect((validatePackBody(m5) as any).code).toBe('E_UNKNOWN_FIELD');
  });
  it('rejects authority-shaped keys in open maps; not in content', () => {
    const m = maximalBody(); (m.testRuns[0].toolVersions as any).signature = 'x'; expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
    const ok = maximalBody(); (ok.files[0] as any).content = 'sign grant token apply seed'; (ok.files[0] as any).originalSizeBytes = 27; (ok.files[0] as any).includedByteEnd = 27;
    expect(validatePackBody(ok).ok).toBe(true);
  });
});

describe('contract decision 1: snapshot subject + base pair', () => {
  it('accepts a valid base pair; rejects a half pair', () => {
    const ok = clone(minimalBody()); (ok as any).baseCommit = 'e'.repeat(40); (ok as any).baseTree = 'f'.repeat(40); expect(validatePackBody(ok).ok).toBe(true);
    const bad = clone(minimalBody()); (bad as any).baseCommit = 'e'.repeat(40); expect((validatePackBody(bad) as any).code).toBe('E_BASE_PAIR');
  });
});

describe('contract decision 6: limits are registry-owned, not self-declared', () => {
  it('rejects an unknown limits profile', () => {
    const m = clone(minimalBody()); (m as any).limitsProfileId = 'evil'; expect((validatePackBody(m) as any).code).toBe('E_LIMIT_PROFILE');
  });
});

describe('contract decision 7: length-framed injective test identity', () => {
  it('["a","b"] and ["a b"] are distinct (no false collision)', () => {
    const m = maximalBody();
    (m as any).testRuns = [
      { command: ['a', 'b'], cwdRelative: '.', exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 0, stderrBytes: 0, stdoutExcerpt: '', durationMs: null, toolVersions: {} },
      { command: ['a b'], cwdRelative: '.', exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 0, stderrBytes: 0, stdoutExcerpt: '', durationMs: null, toolVersions: {} },
    ];
    expect(validatePackBody(m).ok).toBe(true);
  });
  it('duplicate test identities are rejected', () => {
    const m = maximalBody();
    const t = { command: ['x'], cwdRelative: '.', exitCode: 0, stdoutSha256: '3'.repeat(64), stderrSha256: '4'.repeat(64), stdoutBytes: 0, stderrBytes: 0, stdoutExcerpt: '', durationMs: null, toolVersions: {} };
    (m as any).testRuns = [clone(t), clone(t)];
    expect((validatePackBody(m) as any).code).toBe('E_DUP_TEST');
  });
});

describe('contract decision 8: content length vs byte range', () => {
  it('rejects utf8 and base64 length mismatches', () => {
    const u = maximalBody(); (u.files[0] as any).includedByteEnd = 3; (u.files[0] as any).originalSizeBytes = 5; (u.files[0] as any).truncated = true;
    expect((validatePackBody(u) as any).code).toBe('E_CONTENT_LENGTH');
    const b = maximalBody(); (b.files[1] as any).includedByteEnd = 2; (b.files[1] as any).originalSizeBytes = 3; (b.files[1] as any).truncated = true;
    expect((validatePackBody(b) as any).code).toBe('E_CONTENT_LENGTH');
  });
});

describe('contract decision 9: relative POSIX, NFC, no raw NUL, safe ints', () => {
  it('rejects absolute / traversal / backslash paths', () => {
    for (const bad of ['/etc/x', '../x', 'a\\b']) { const m = maximalBody(); (m.files[0] as any).path = bad; expect((validatePackBody(m) as any).code).toBe('E_REL_PATH'); }
  });
  it('rejects a non-NFC path and a raw NUL in any string', () => {
    const nfc = maximalBody(); (nfc.files[0] as any).path = 'café.ts'; expect((validatePackBody(nfc) as any).code).toBe('E_NOT_NFC');
    const nul = clone(minimalBody()); (nul as any).repoId = 'x' + NUL + 'y'; expect((validatePackBody(nul) as any).code).toBe('E_NUL');
  });
  it('rejects bad hashes / gitshas / integers', () => {
    const s = clone(minimalBody()); (s as any).headTree = 'B'.repeat(40); expect((validatePackBody(s) as any).code).toBe('E_BAD_GITSHA');
    const i = maximalBody(); (i.files[0] as any).originalSizeBytes = 1.5; expect((validatePackBody(i) as any).code).toBe('E_BAD_INTEGER');
  });
});

describe('contract decision 10: secret-content refusal + closed omission enum', () => {
  it('refuses a pack whose included text content is secret-shaped', () => {
    const m = maximalBody(); const secret = 'key=sk-or-abcdefghijklmnop0123';
    (m.files[0] as any).content = secret; (m.files[0] as any).originalSizeBytes = secret.length; (m.files[0] as any).includedByteEnd = secret.length;
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('rejects a narrative omission reason (enum only)', () => {
    const m = maximalBody(); (m.omissions[0] as any).reason = 'it looked scary';
    expect((validatePackBody(m) as any).code).toBe('E_OMISSION_REASON');
  });
});

describe('catalogue binding + downgrade', () => {
  it('rejects a wrong catalogueId and detects catalogue mutation', () => {
    const m = clone(minimalBody()); (m as any).catalogueId = '0'.repeat(64); expect((validatePackBody(m) as any).code).toBe('E_CATALOGUE_ID');
    const mutated = { ...SECRET_CATALOGUE, patterns: [...SECRET_CATALOGUE.patterns, { id: 'x', pattern: 'z', flags: 'g' }] };
    expect(sha256Hex(canonicalBytes(mutated))).not.toBe(catalogueId());
    expect(scanForSecrets('this discusses tokens and signatures').length).toBe(0);
  });
});

describe('fence derived from packDigest, collision-free (not stored)', () => {
  it('increments past a colliding candidate', () => {
    const pd = packDigest(minimalBody());
    const candidate0 = sha256Hex(new TextEncoder().encode(`aukora-fu-evidence-fence-v1|${pd}|0`)).slice(0, 32);
    const contents = [fenceOpen(candidate0)]; // force a collision at counter 0
    const nonce = deriveFenceNonce(pd, contents);
    expect(nonce).not.toBe(candidate0);
    expect(fenceCollisionFree(nonce, contents)).toBe(true);
  });
});

describe('envelope: digest echo + identical seat render (no timestamp)', () => {
  it('seals to {body, packDigest} only, verifies, rejects tamper', () => {
    const env = sealEnvelope(minimalBody());
    expect(Object.keys(env).sort()).toEqual(['body', 'packDigest']);
    expect(verifyEnvelope(env)).toBe(true);
    const bad = { ...env, packDigest: env.packDigest.slice(0, 63) + (env.packDigest[63] === 'a' ? 'b' : 'a') };
    expect((validateEnvelope(bad) as any).code).toBe('E_DIGEST_MISMATCH');
  });
  it('renders byte-identically for every seat', () => {
    const env = sealEnvelope(maximalBody());
    expect(Buffer.from(renderForSeat(env, 'A')).equals(Buffer.from(renderForSeat(env, 'B')))).toBe(true);
  });
});
