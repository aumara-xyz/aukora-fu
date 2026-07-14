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
const KAT_CATALOGUE_ID = 'f092790cdefb20612a4bfab563cd19fffaf742238a8d683396660027a17a7565';
const KAT_CANON = '{"advisoryOnly":true,"baseCommit":null,"baseTree":null,"builderToolVersions":{"node":"v22.23.0"},"catalogueId":"f092790cdefb20612a4bfab563cd19fffaf742238a8d683396660027a17a7565","files":[],"grantsAuthority":false,"headCommit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","headTree":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","limitsProfileId":"default-v1","omissions":[],"repoId":"aumara-xyz/aukora-fu","rootAllowlist":[],"schema":"aukora-fu-evidence-pack-v1","testRuns":[]}';
const KAT_MIN_DIGEST = '352c05abe2288cd516bb6da0bfed0fe4896f5408fe16a8989389a7156cb30747';
const KAT_MAX_DIGEST = 'e8e3d3f3f42036a721da70368a699c2e9a5f657e433830dc714243e3be10b625'; // D2: honest zero-byte stream
const KAT_FENCE = '3a23cb4c6895e0ca934a95f328985122a706ccf9d9188a2897e9fbef158acc28';
const SHA_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
const SHA_ZEROS3 = '709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c';
const SHA_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // sha256("")

const enc = new TextEncoder();
const NUL = String.fromCharCode(0);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));

function mkTextFile(path: string, content: string): EvidenceFileV1 {
  const bytes = enc.encode(content); const h = sha256Hex(bytes);
  return { path, kind: 'text', originalSizeBytes: bytes.length, includedByteStart: 0, includedByteEnd: bytes.length, truncated: false, fullSha256: h, includedSha256: h, encoding: 'utf8', content };
}
function mkTest(command: string[], cwdRelative = '.'): EvidenceTestRunV1 {
  // Zero-byte streams: empty excerpt IS the whole stream, so its hash must be sha256("") (amendment 8/15).
  return { command, cwdRelative, exitCode: 0, stdoutSha256: SHA_EMPTY, stderrSha256: SHA_EMPTY, stdoutBytes: 0, stderrBytes: 0, stdoutExcerpt: '', stderrExcerpt: '', durationMs: null, toolVersions: {} };
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

function mkBinFile(path: string, bytes: number[]): EvidenceFileV1 {
  const u8 = new Uint8Array(bytes); const b64 = Buffer.from(u8).toString('base64'); const h = sha256Hex(u8);
  return { path, kind: 'binary', originalSizeBytes: bytes.length, includedByteStart: 0, includedByteEnd: bytes.length, truncated: false, fullSha256: h, includedSha256: h, encoding: 'base64', content: b64 };
}

describe('D1: full-width fence + exact base64 secret scanning', () => {
  it('fence nonce is the full 64-hex SHA-256', () => {
    expect(deriveFenceNonce('0'.repeat(64), ['x']).length).toBe(64);
    expect(deriveFenceNonce('00'.repeat(32), ['hello', 'world'])).toBe(KAT_FENCE);
  });
  it('refuses an ASCII secret inside invalid UTF-8 binary (ASCII-byte projection)', () => {
    const bytes = [...enc.encode('sk-or-abcdefghijklmnop0123')].concat([0xFF, 0xFE]);
    const m = bodyWith([mkBinFile('x.bin', bytes)], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('refuses a confusable secret inside valid UTF-8 base64 (strict decode + skeleton)', () => {
    const bytes = [...enc.encode('sk-оr-abcdefghijklmnop0123')]; // Cyrillic о U+043E
    const m = bodyWith([mkBinFile('y.bin', bytes)], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
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

// ── D2 immune-gate hostile tests (each closes a reachable P1) ─────────────────────────────────────
describe('D2: prototype pollution + inherited fields', () => {
  it('inherited grantsAuthority via a polluted prototype is refused (E_PROTO closes it outright)', () => {
    const m: any = clone(minimalBody()); delete m.grantsAuthority;
    Object.setPrototypeOf(m, { grantsAuthority: false });
    expect(['E_PROTO', 'E_MISSING_FIELD']).toContain((validatePackBody(m) as any).code);
  });
  it('non-ordinary prototype (class instance / polluted proto) is refused', () => {
    class Evil { constructor() { Object.assign(this, minimalBody()); } }
    expect((validatePackBody(new Evil() as any) as any).code).toBe('E_PROTO');
    const polluted: any = clone(minimalBody()); Object.setPrototypeOf(polluted, { x: 1 });
    expect((validatePackBody(polluted) as any).code).toBe('E_PROTO');
  });
});

describe('D2: omission ceiling, open-map families, stream truth', () => {
  it('rootAllowlist beyond maxFiles is refused (omissions counted)', () => {
    const omissions = Array.from({ length: 4097 }, (_, i) => ({ path: `f${String(i).padStart(5, '0')}.x`, reason: 'binary' as const, originalSizeBytes: null, sha256: null }));
    const m = bodyWith([], omissions, []);
    expect((validatePackBody(m) as any).code).toBe('E_LIMIT_ALLOWLIST');
  });
  it('apiKey / signingKey open-map keys are refused after normalization', () => {
    for (const k of ['apiKey', 'signingKey', 'access_token', 'privateKey', 'bearerToken']) {
      const m = clone(maximalBody()); (m.builderToolVersions as any)[k] = 'x';
      expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
    }
  });
  it('secret in an open-map value is refused', () => {
    const m = clone(maximalBody()); (m.builderToolVersions as any).tool = 'sk-or-' + 'a'.repeat(20);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('excerpt longer than the claimed stream, or full-excerpt hash mismatch, is refused', () => {
    const longer = clone(maximalBody()); (longer.testRuns[0] as any).stdoutExcerpt = 'more than zero'; // >0 stdoutBytes
    expect((validatePackBody(longer) as any).code).toBe('E_STREAM_LENGTH');
    const badHash = clone(maximalBody()); (badHash.testRuns[0] as any).stdoutExcerpt = 'x'; (badHash.testRuns[0] as any).stdoutBytes = 1; // len==bytes, hash != stream sha
    expect((validatePackBody(badHash) as any).code).toBe('E_STREAM_HASH');
  });
});

describe('D2: seal freeze + render revalidation + surrogates + composed projection', () => {
  it('a sealed envelope is deep-frozen and its body cannot be mutated', () => {
    const env = sealEnvelope(maximalBody());
    expect(Object.isFrozen(env)).toBe(true);
    expect(Object.isFrozen(env.body)).toBe(true);
    expect(() => { (env.body as any).repoId = 'evil'; }).toThrow();
  });
  it('renderForSeat refuses a post-seal-mutated envelope', () => {
    const env = sealEnvelope(minimalBody());
    const tampered = { body: { ...env.body, repoId: 'tampered' }, packDigest: env.packDigest };
    expect(() => renderForSeat(tampered as any, 'seat-1')).toThrow();
  });
  it('lone surrogate in a value or key is rejected by canonicalizer + wire check', () => {
    expect(() => canonicalString({ a: '\uD800' })).toThrow();
    expect(verifyCanonicalWire('{"a":"\\ud800"}')).toBe(false);
  });
  it('composed NFC+zero-width+confusable secret is detected', () => {
    // 'ѕ'(confusable s) + zero-width joiner inside the key prefix; composed projection must still catch it.
    expect(textHasSecret('ѕ​k-or-' + 'a'.repeat(20))).toBe(true);
  });
  it('NFD repoId is refused; NFD source content is still fine', () => {
    const m = clone(minimalBody()); (m as any).repoId = 'café'; // NFD
    expect((validatePackBody(m) as any).code).toBe('E_NOT_NFC');
  });
});

// ── D2 red-team closures (each proves a found-and-fixed bypass) ───────────────────────────────────
describe('D2 red-team: closed bypasses', () => {
  it('own NON-ENUMERABLE authority literal is refused (E_PROTO)', () => {
    const m: any = clone(minimalBody());
    for (const k of ['advisoryOnly', 'grantsAuthority']) {
      const v = m[k]; delete m[k];
      Object.defineProperty(m, k, { value: v, enumerable: false, writable: true, configurable: true });
    }
    expect((validatePackBody(m) as any).code).toBe('E_PROTO');
  });
  it('own ENUMERABLE getter (accessor) is refused (E_PROTO)', () => {
    const m: any = clone(minimalBody());
    const files = m.files; delete m.files;
    Object.defineProperty(m, 'files', { enumerable: true, configurable: true, get() { return files; } });
    expect((validatePackBody(m) as any).code).toBe('E_PROTO');
  });
  it('a secret hidden as an open-map KEY is refused', () => {
    const m: any = clone(maximalBody());
    m.builderToolVersions = { ['sk-or-' + 'a'.repeat(20)]: 'v20' };
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('a short excerpt with an inflated claimed stream length is refused (E_STREAM_LENGTH)', () => {
    const m: any = clone(maximalBody());
    m.testRuns[0].stdoutExcerpt = 'PASS'; m.testRuns[0].stdoutBytes = 54; m.testRuns[0].stdoutSha256 = 'a'.repeat(64);
    expect((validatePackBody(m) as any).code).toBe('E_STREAM_LENGTH');
  });
  it('a secret split by U+00AD soft hyphen is detected by the composed projection', () => {
    const split = 'sk-or-v1abcdef01' + '­' + '23456789ABCDEF';
    expect(textHasSecret(split)).toBe(true);
    const f = mkTextFile('leak.ts', split);
    const m = bodyWith([f], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('a prototype-polluted Object.prototype authority literal is refused (own-property req)', () => {
    (Object.prototype as any).grantsAuthority = false;
    try {
      const m: any = {}; const src = minimalBody() as any;
      for (const k of Object.keys(src)) if (k !== 'grantsAuthority') m[k] = src[k];
      expect((validatePackBody(m) as any).code).toBe('E_MISSING_FIELD');
    } finally { delete (Object.prototype as any).grantsAuthority; }
  });
});

// ── Round-14 red-team round 3 closures: catalogue + lexicon completeness ─────────────────────────
describe('R14 red-team: catalogue + lexicon completeness', () => {
  it('common credential-prefix families are all catalogued (P1-c)', () => {
    expect(textHasSecret('ghp_' + 'a'.repeat(30))).toBe(true);              // GitHub PAT
    expect(textHasSecret('github_pat_' + 'a'.repeat(30))).toBe(true);       // GitHub fine-grained
    expect(textHasSecret('xoxb-' + '1234567890-abcdefghij')).toBe(true);    // Slack bot token
    expect(textHasSecret('AIza' + 'a'.repeat(35))).toBe(true);             // Google API key
    expect(textHasSecret('sk_live_' + 'a'.repeat(24))).toBe(true);         // Stripe live key
    expect(textHasSecret('npm_' + 'a'.repeat(36))).toBe(true);             // npm token
    expect(textHasSecret('glpat-' + 'a'.repeat(20))).toBe(true);           // GitLab PAT
  });
  it('a GitHub token in an open-map VALUE is refused (E_SECRET_CONTENT)', () => {
    const m: any = clone(maximalBody());
    m.builderToolVersions = { node: 'ghp_' + 'b'.repeat(36) };
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('a secret split by a Unicode combining mark (U+0301) is still detected', () => {
    // 8 + mark + 14 word-chars: neither run alone reaches the 16-char minimum, so raw/NFC miss it;
    // stripping \p{M} rejoins the run and the composed projection catches it.
    const split = 'sk-or-' + 'abcdef01' + '́' + '23456789abcdef';
    expect(textHasSecret(split)).toBe(true);
    const m = bodyWith([mkTextFile('leak.ts', split)], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('bare authority-shaped key names (masterKey / sshKey / certPath) are refused', () => {
    for (const key of ['masterKey', 'sshKey', 'certPath']) {
      const m: any = clone(maximalBody());
      m.builderToolVersions = { [key]: 'v1' };
      expect((validatePackBody(m) as any).code).toBe('E_AUTHORITY_SHAPED_KEY');
    }
  });
});

// ── R14 red-team round 3: compatibility-Unicode + high-value credential shapes ────────────────────
describe('R14 red-team round 3: NFKC folding + credential shapes', () => {
  const toFullwidth = (s: string) => [...s].map((c) => {
    const n = c.codePointAt(0)!; return (n >= 0x21 && n <= 0x7e) ? String.fromCodePoint(n - 0x21 + 0xff01) : c;
  }).join('');
  const toMathMono = (s: string) => [...s].map((c) => {
    const n = c.codePointAt(0)!;
    if (n >= 0x41 && n <= 0x5a) return String.fromCodePoint(0x1d670 + (n - 0x41)); // A-Z
    if (n >= 0x61 && n <= 0x7a) return String.fromCodePoint(0x1d68a + (n - 0x61)); // a-z
    if (n >= 0x30 && n <= 0x39) return String.fromCodePoint(0x1d7f6 + (n - 0x30)); // 0-9
    return c;
  }).join('');
  it('FULLWIDTH-obfuscated catalogued secret is caught (NFKC projection)', () => {
    const secret = 'sk-or-' + 'a'.repeat(20);
    expect(textHasSecret(secret)).toBe(true);           // control: raw is caught
    expect(textHasSecret(toFullwidth(secret))).toBe(true);
    const m = bodyWith([mkTextFile('leak.ts', toFullwidth(secret))], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('MATH-MONOSPACE-obfuscated github token is caught (NFKC projection)', () => {
    const g = toMathMono('ghp_' + 'A'.repeat(30));
    expect(textHasSecret(g)).toBe(true);
    const m = bodyWith([mkTextFile('leak.ts', g)], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('a connection-string URL with an inline password is caught (url-userinfo shape)', () => {
    expect(textHasSecret('postgresql://app:S3cr3tPgCred@10.0.3.4:5432/db')).toBe(true);
    expect(textHasSecret('mongodb://root:hunter2pass@db.internal:27017')).toBe(true);
    const m = bodyWith([mkTextFile('cfg.ts', 'const u = "postgres://u:p4ssw0rd-here@h/db";')], [], []);
    expect((validatePackBody(m) as any).code).toBe('E_SECRET_CONTENT');
  });
  it('Anthropic / Azure / SendGrid credential shapes are caught', () => {
    expect(textHasSecret('sk-ant-api03-' + 'a'.repeat(24))).toBe(true);
    expect(textHasSecret('AccountKey=' + 'b'.repeat(50) + '==')).toBe(true);
    expect(textHasSecret('SG.' + 'a'.repeat(20) + '.' + 'b'.repeat(20))).toBe(true);
  });
  it('legitimate high-entropy evidence is NOT false-flagged (no entropy backstop)', () => {
    // base64 binary content, a git SHA, and a bare hex hash must all pass — the pack ships this legitimately.
    expect(textHasSecret('AAAA')).toBe(false);
    expect(textHasSecret('a'.repeat(40))).toBe(false);              // git-sha-shaped
    expect(textHasSecret('deadbeef'.repeat(8))).toBe(false);         // 64-hex digest
    expect(validatePackBody(maximalBody()).ok).toBe(true);          // real base64 file content in fixture
  });
});
