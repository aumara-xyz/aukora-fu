// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * Recursive, fail-closed, positive-allow-list validator (Round-12 immune gate). Pure: no I/O.
 * Enforces the settled contract plus the Commit-D amendments: full vs. included content hashes
 * (recomputed from decoded bytes; equal iff complete), files/omissions/rootAllowlist exact partition,
 * relative-POSIX + NFC path discipline (file/omission/allowlist paths and test cwd, "." only for cwd),
 * canonical base64 round-trip, projection-based secret refusal (raw/NFC/zero-width/confusable) over
 * utf8 content, base64-decoded-as-text, and stdout/stderr excerpts, ASCII open-map keys + NFC values,
 * UTF-8-byte-length-framed unique test identity, registry-owned limits, bound catalogueId, and no raw NUL.
 */
import { EVIDENCE_PACK_SCHEMA, EvidenceErrorCode, ValidationResult, OMISSION_REASONS, LIMITS_PROFILES } from './types';
import { canonicalBytes } from './canonical';
import { packDigest, sha256Hex } from './digest';
import { catalogueId, textHasSecret } from './catalogue';

const SHA256_RE = /^[0-9a-f]{64}$/;
const GITSHA_RE = /^[0-9a-f]{40}$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const MAP_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const AUTHORITY_KEY_RE = /(?:^|[_-])(?:sign|signed|signature|grant|grants|authoriz\w*|token|apply|seed|privatekey|mutate|approve|unlock)(?:[_-]|$)/i;
/** D2 amendment 4: normalized-substring denylist for open-map keys. A key is lowercased and stripped of
 *  separators (`_ - . space`) before screening, so `Api-Key`, `api_key`, `A p i K e y` all collapse to
 *  `apikey`. Any of these families as a substring refuses the map. */
const MAP_KEY_DENY = [
  'apikey', 'signingkey', 'privatekey', 'accesstoken', 'bearertoken', 'credential', 'password',
  'secret', 'seed', 'token', 'approve', 'apply', 'grant', 'unlock', 'mutate', 'signature',
  'sign', 'signed', 'signing', 'authoriz',
];
function normalizeMapKey(k: string): string { return k.toLowerCase().replace(/[\s._-]/g, ''); }

const PACK_KEYS = ['schema', 'advisoryOnly', 'grantsAuthority', 'repoId', 'headCommit', 'headTree', 'baseCommit', 'baseTree', 'files', 'omissions', 'testRuns', 'rootAllowlist', 'limitsProfileId', 'builderToolVersions', 'catalogueId'];
const FILE_KEYS = ['path', 'kind', 'originalSizeBytes', 'includedByteStart', 'includedByteEnd', 'truncated', 'fullSha256', 'includedSha256', 'encoding', 'content'];
const OMISSION_KEYS = ['path', 'reason', 'originalSizeBytes', 'sha256'];
const TEST_KEYS = ['command', 'cwdRelative', 'exitCode', 'stdoutSha256', 'stderrSha256', 'stdoutBytes', 'stderrBytes', 'stdoutExcerpt', 'stderrExcerpt', 'durationMs', 'toolVersions'];

const encoder = new TextEncoder();
const OK: ValidationResult = { ok: true };
function err(code: EvidenceErrorCode, path: string, message: string): ValidationResult { return { ok: false, code, path, message }; }
function isPlainObject(v: unknown): v is Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v); }
/** D2 amendments 1-2: accept only ordinary (Object.prototype or null-proto) objects — reject class
 *  instances and prototype-polluted objects, whose inherited members can smuggle authority literals. */
function isOrdinaryObject(v: unknown): boolean {
  if (!isPlainObject(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}
function hasOwn(v: object, k: string): boolean { return Object.prototype.hasOwnProperty.call(v, k); }
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) { const n = s.charCodeAt(i + 1); if (!(n >= 0xDC00 && n <= 0xDFFF)) return true; i++; }
    else if (c >= 0xDC00 && c <= 0xDFFF) return true;
  }
  return false;
}
function safeIntGE0(v: unknown): v is number { return typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0; }
function safeInt(v: unknown): v is number { return typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0); }
function utf8Len(s: string): number { return encoder.encode(s).length; }
function isNfc(s: string): boolean { return s.normalize('NFC') === s; }
function decodeBase64Canonical(s: string): Uint8Array | null {
  if (s.length % 4 !== 0 || !BASE64_RE.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  if (buf.toString('base64') !== s) return null; // canonical round-trip
  return new Uint8Array(buf);
}

/** Deterministic ASCII-byte projection (D1): keep printable ASCII + TAB/LF/CR; every other byte -> LF. */
function asciiByteProjection(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += ((b >= 0x20 && b <= 0x7E) || b === 0x09 || b === 0x0A || b === 0x0D) ? String.fromCharCode(b) : '\n';
  }
  return s;
}

/** D1 base64 secret scan: always scan the ASCII-byte projection (catches ASCII secrets inside invalid
 *  UTF-8 binary); additionally strict-decode UTF-8 and, on success, run raw/NFC/zero-width/confusable
 *  projections (catches confusable secrets inside valid UTF-8). */
function decodedBytesHaveSecret(bytes: Uint8Array): boolean {
  if (textHasSecret(asciiByteProjection(bytes))) return true;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (textHasSecret(text)) return true;
  } catch { /* invalid UTF-8: the ASCII projection already covered it */ }
  return false;
}

function checkString(v: unknown, p: string): ValidationResult {
  if (typeof v !== 'string') return err('E_WRONG_TYPE', p, 'expected string');
  if (v.indexOf('\u0000') !== -1) return err('E_NUL', p, 'raw NUL in string');
  if (hasLoneSurrogate(v)) return err('E_INVALID_UTF8', p, 'lone surrogate');
  return OK;
}
function checkRelPosixPath(v: unknown, p: string): ValidationResult {
  const s = checkString(v, p); if (!s.ok) return s;
  const str = v as string;
  if (!isNfc(str)) return err('E_NOT_NFC', p, 'path not NFC');
  if (str.length === 0 || str.charAt(0) === '/' || str.indexOf('\\') !== -1 || /(?:^|\/)\.\.?(?:\/|$)/.test(str) || /^[A-Za-z]:/.test(str)) {
    return err('E_REL_PATH', p, 'not a relative POSIX path');
  }
  if (textHasSecret(str)) return err('E_SECRET_CONTENT', p, 'secret-shaped path'); // D2 amendment 5
  return OK;
}
function checkHex(v: unknown, re: RegExp, code: EvidenceErrorCode, p: string): ValidationResult {
  const s = checkString(v, p); if (!s.ok) return s;
  if (!re.test(v as string)) return err(code, p, `bad format at ${p}`);
  return OK;
}
function closedObject(v: unknown, keys: readonly string[], p: string): ValidationResult {
  if (!isPlainObject(v)) return err('E_NOT_OBJECT', p, 'expected object');
  if (!isOrdinaryObject(v)) return err('E_PROTO', p, 'non-ordinary object prototype');
  for (const k of Object.keys(v)) if (keys.indexOf(k) === -1) return err('E_UNKNOWN_FIELD', `${p}.${k}`, `unknown field ${k}`);
  for (const k of keys) if (!hasOwn(v, k)) return err('E_MISSING_FIELD', `${p}.${k}`, `missing own field ${k}`);
  return OK;
}
/** Open string→string map: ASCII-syntax keys (authority-screened + normalized denylist, D2 amendment 4),
 *  NFC + secret-free string values (decision 9 + D2 amendment 5). Ordinary prototype required. */
function checkStringMap(v: unknown, p: string): ValidationResult {
  if (!isPlainObject(v)) return err('E_NOT_OBJECT', p, 'expected object');
  if (!isOrdinaryObject(v)) return err('E_PROTO', p, 'non-ordinary object prototype');
  for (const k of Object.keys(v)) {
    if (AUTHORITY_KEY_RE.test(k)) return err('E_AUTHORITY_SHAPED_KEY', `${p}.${k}`, `authority-shaped key ${k}`);
    if (!MAP_KEY_RE.test(k)) return err('E_MAP_KEY', `${p}.${k}`, 'key not pinned-ASCII syntax');
    const nk = normalizeMapKey(k);
    for (const bad of MAP_KEY_DENY) if (nk.indexOf(bad) !== -1) return err('E_MAP_KEY_DENY', `${p}.${k}`, `denied key family ${bad}`);
    const val = (v as Record<string, unknown>)[k];
    const cv = checkString(val, `${p}.${k}`); if (!cv.ok) return cv;
    if (!isNfc(val as string)) return err('E_MAP_VALUE_NFC', `${p}.${k}`, 'value not NFC');
    if (textHasSecret(val as string)) return err('E_SECRET_CONTENT', `${p}.${k}`, 'secret-shaped map value');
  }
  return OK;
}
function checkPathArraySortedUnique(v: unknown, p: string): ValidationResult {
  if (!Array.isArray(v)) return err('E_WRONG_TYPE', p, 'expected array');
  for (let i = 0; i < v.length; i++) {
    const c = checkRelPosixPath(v[i], `${p}[${i}]`); if (!c.ok) return c;
    if (i > 0) {
      if ((v[i - 1] as string) > (v[i] as string)) return err('E_ARRAY_UNSORTED', `${p}[${i}]`, 'not sorted');
      if ((v[i - 1] as string) === (v[i] as string)) return err('E_DUP_PATH', `${p}[${i}]`, 'duplicate');
    }
  }
  return OK;
}

function checkFile(v: unknown, p: string): ValidationResult {
  const c = closedObject(v, FILE_KEYS, p); if (!c.ok) return c;
  const o = v as Record<string, unknown>;
  const cp = checkRelPosixPath(o.path, `${p}.path`); if (!cp.ok) return cp;
  if (o.kind !== 'text' && o.kind !== 'binary') return err('E_BAD_ENUM', `${p}.kind`, 'kind');
  if (!safeIntGE0(o.originalSizeBytes)) return err('E_BAD_INTEGER', `${p}.originalSizeBytes`, 'int>=0');
  if (!safeIntGE0(o.includedByteStart)) return err('E_BAD_INTEGER', `${p}.includedByteStart`, 'int>=0');
  if (!safeIntGE0(o.includedByteEnd)) return err('E_BAD_INTEGER', `${p}.includedByteEnd`, 'int>=0');
  if (typeof o.truncated !== 'boolean') return err('E_WRONG_TYPE', `${p}.truncated`, 'boolean');
  const cfs = checkHex(o.fullSha256, SHA256_RE, 'E_BAD_SHA', `${p}.fullSha256`); if (!cfs.ok) return cfs;
  const cis = checkHex(o.includedSha256, SHA256_RE, 'E_BAD_SHA', `${p}.includedSha256`); if (!cis.ok) return cis;
  if (o.encoding !== 'utf8' && o.encoding !== 'base64') return err('E_BAD_ENUM', `${p}.encoding`, 'encoding');
  const cc = checkString(o.content, `${p}.content`); if (!cc.ok) return cc;
  const start = o.includedByteStart as number, end = o.includedByteEnd as number, orig = o.originalSizeBytes as number;
  if (!(start <= end && end <= orig)) return err('E_BAD_RANGE', p, 'byte range');
  if (o.truncated !== (start > 0 || end < orig)) return err('E_BAD_RANGE', `${p}.truncated`, 'truncated flag inconsistent');
  if (o.kind === 'binary' && o.encoding !== 'base64') return err('E_BINARY_INLINE', `${p}.encoding`, 'binary must be base64');
  if (o.kind === 'text' && o.encoding !== 'utf8') return err('E_BINARY_INLINE', `${p}.encoding`, 'text must be utf8');

  const content = o.content as string;
  let bytes: Uint8Array;
  let secret: boolean;
  if (o.encoding === 'utf8') {
    bytes = encoder.encode(content);
    secret = textHasSecret(content);
  } else {
    const decoded = decodeBase64Canonical(content);
    if (decoded === null) return err('E_BASE64_NONCANONICAL', `${p}.content`, 'non-canonical base64');
    bytes = decoded;
    secret = decodedBytesHaveSecret(bytes);
  }
  const included = end - start;
  if (bytes.length !== included) return err('E_CONTENT_LENGTH', `${p}.content`, 'decoded length != included range');
  if (sha256Hex(bytes) !== o.includedSha256) return err('E_HASH_INCLUDED', `${p}.includedSha256`, 'included hash mismatch');
  if (start === 0 && end === orig && o.includedSha256 !== o.fullSha256) return err('E_HASH_COMPLETE', `${p}`, 'complete file: includedSha256 must equal fullSha256');
  if (secret) return err('E_SECRET_CONTENT', `${p}.content`, 'secret-shaped included content');
  return OK;
}

function checkOmission(v: unknown, p: string): ValidationResult {
  const c = closedObject(v, OMISSION_KEYS, p); if (!c.ok) return c;
  const o = v as Record<string, unknown>;
  const cp = checkRelPosixPath(o.path, `${p}.path`); if (!cp.ok) return cp;
  if (typeof o.reason !== 'string' || (OMISSION_REASONS as readonly string[]).indexOf(o.reason) === -1) return err('E_OMISSION_REASON', `${p}.reason`, 'reason not a closed enum code');
  if (o.originalSizeBytes !== null && !safeIntGE0(o.originalSizeBytes)) return err('E_BAD_INTEGER', `${p}.originalSizeBytes`, 'int>=0|null');
  if (o.sha256 !== null) { const cs = checkHex(o.sha256, SHA256_RE, 'E_BAD_SHA', `${p}.sha256`); if (!cs.ok) return cs; }
  return OK;
}

function checkTest(v: unknown, p: string): ValidationResult {
  const c = closedObject(v, TEST_KEYS, p); if (!c.ok) return c;
  const o = v as Record<string, unknown>;
  if (!Array.isArray(o.command)) return err('E_WRONG_TYPE', `${p}.command`, 'array');
  for (let i = 0; i < o.command.length; i++) {
    const cs = checkString(o.command[i], `${p}.command[${i}]`); if (!cs.ok) return cs;
    if (!isNfc(o.command[i] as string)) return err('E_NOT_NFC', `${p}.command[${i}]`, 'argv not NFC');
    if (textHasSecret(o.command[i] as string)) return err('E_SECRET_CONTENT', `${p}.command[${i}]`, 'secret-shaped argv'); // D2 amendment 5
  }
  const cw = checkString(o.cwdRelative, `${p}.cwdRelative`); if (!cw.ok) return cw;
  const cwd = o.cwdRelative as string;
  if (textHasSecret(cwd)) return err('E_SECRET_CONTENT', `${p}.cwdRelative`, 'secret-shaped cwd'); // D2 amendment 5
  if (cwd !== '.') { const cr = checkRelPosixPath(cwd, `${p}.cwdRelative`); if (!cr.ok) return err('E_CWD', `${p}.cwdRelative`, 'cwd must be relative POSIX or "."'); }
  if (!safeInt(o.exitCode)) return err('E_BAD_INTEGER', `${p}.exitCode`, 'int');
  const so = checkHex(o.stdoutSha256, SHA256_RE, 'E_BAD_SHA', `${p}.stdoutSha256`); if (!so.ok) return so;
  const se = checkHex(o.stderrSha256, SHA256_RE, 'E_BAD_SHA', `${p}.stderrSha256`); if (!se.ok) return se;
  if (!safeIntGE0(o.stdoutBytes)) return err('E_BAD_INTEGER', `${p}.stdoutBytes`, 'int>=0');
  if (!safeIntGE0(o.stderrBytes)) return err('E_BAD_INTEGER', `${p}.stderrBytes`, 'int>=0');
  const ex = checkString(o.stdoutExcerpt, `${p}.stdoutExcerpt`); if (!ex.ok) return ex;
  const ee = checkString(o.stderrExcerpt, `${p}.stderrExcerpt`); if (!ee.ok) return ee;
  if (textHasSecret(o.stdoutExcerpt as string) || textHasSecret(o.stderrExcerpt as string)) return err('E_SECRET_CONTENT', `${p}.excerpt`, 'secret-shaped test excerpt');
  // D2 amendment 8: an excerpt can never exceed its stream; a stream-length excerpt IS the whole stream,
  // so it must hash to the claimed stream digest (defeats "tiny honest stream, huge lying excerpt").
  const outLen = utf8Len(o.stdoutExcerpt as string);
  if (outLen > (o.stdoutBytes as number)) return err('E_STREAM_EXCERPT', `${p}.stdoutExcerpt`, 'excerpt exceeds stdout stream bytes');
  if (outLen === (o.stdoutBytes as number) && sha256Hex(encoder.encode(o.stdoutExcerpt as string)) !== o.stdoutSha256) return err('E_STREAM_EXCERPT', `${p}.stdoutSha256`, 'complete stdout excerpt must hash to stdoutSha256');
  const errLen = utf8Len(o.stderrExcerpt as string);
  if (errLen > (o.stderrBytes as number)) return err('E_STREAM_EXCERPT', `${p}.stderrExcerpt`, 'excerpt exceeds stderr stream bytes');
  if (errLen === (o.stderrBytes as number) && sha256Hex(encoder.encode(o.stderrExcerpt as string)) !== o.stderrSha256) return err('E_STREAM_EXCERPT', `${p}.stderrSha256`, 'complete stderr excerpt must hash to stderrSha256');
  if (o.durationMs !== null && !safeIntGE0(o.durationMs)) return err('E_BAD_INTEGER', `${p}.durationMs`, 'int>=0|null');
  const tv = checkStringMap(o.toolVersions, `${p}.toolVersions`); if (!tv.ok) return tv;
  return OK;
}

function checkArraySorted(v: unknown, p: string, each: (x: unknown, pp: string) => ValidationResult, key: (x: unknown) => string, dupCode: EvidenceErrorCode | null): ValidationResult {
  if (!Array.isArray(v)) return err('E_WRONG_TYPE', p, 'expected array');
  let prev: string | null = null;
  for (let i = 0; i < v.length; i++) {
    const c = each(v[i], `${p}[${i}]`); if (!c.ok) return c;
    const k = key(v[i]);
    if (prev !== null) {
      if (prev > k) return err('E_ARRAY_UNSORTED', `${p}[${i}]`, 'not sorted');
      if (dupCode !== null && prev === k) return err(dupCode, `${p}[${i}]`, 'duplicate identity');
    }
    prev = k;
  }
  return OK;
}

/** UTF-8 byte-length-framed injective identity (contract decision 10). */
function testIdentity(t: unknown): string {
  const o = t as Record<string, unknown>;
  const cmd = Array.isArray(o.command) ? (o.command as string[]) : [];
  const parts = cmd.map((a) => `${utf8Len(a)}:${a}`).join(',');
  const cwd = String(o.cwdRelative);
  return `${parts}#${utf8Len(cwd)}:${cwd}`;
}

export function validatePackBody(x: unknown): ValidationResult {
  const c = closedObject(x, PACK_KEYS, 'body'); if (!c.ok) return c;
  const b = x as Record<string, unknown>;

  if (b.schema !== EVIDENCE_PACK_SCHEMA) return err('E_SCHEMA', 'body.schema', 'wrong schema');
  if (b.advisoryOnly !== true) return err('E_ADVISORY_LITERAL', 'body.advisoryOnly', 'must be literal true');
  if (b.grantsAuthority !== false) return err('E_ADVISORY_LITERAL', 'body.grantsAuthority', 'must be literal false');

  const cr = checkString(b.repoId, 'body.repoId'); if (!cr.ok) return cr;
  if (!isNfc(b.repoId as string)) return err('E_NOT_NFC', 'body.repoId', 'repoId not NFC'); // D2 amendment 14
  if (textHasSecret(b.repoId as string)) return err('E_SECRET_CONTENT', 'body.repoId', 'secret-shaped repoId'); // D2 amendment 5
  const ch = checkHex(b.headCommit, GITSHA_RE, 'E_BAD_GITSHA', 'body.headCommit'); if (!ch.ok) return ch;
  const ct = checkHex(b.headTree, GITSHA_RE, 'E_BAD_GITSHA', 'body.headTree'); if (!ct.ok) return ct;
  const baseNull = b.baseCommit === null && b.baseTree === null;
  if (!baseNull) {
    if (b.baseCommit === null || b.baseTree === null) return err('E_BASE_PAIR', 'body.base', 'baseCommit and baseTree must both be present or both null');
    const cbc = checkHex(b.baseCommit, GITSHA_RE, 'E_BAD_GITSHA', 'body.baseCommit'); if (!cbc.ok) return cbc;
    const cbt = checkHex(b.baseTree, GITSHA_RE, 'E_BAD_GITSHA', 'body.baseTree'); if (!cbt.ok) return cbt;
  }

  const cf = checkArraySorted(b.files, 'body.files', checkFile, (f) => (f as Record<string, unknown>).path as string, 'E_DUP_PATH'); if (!cf.ok) return cf;
  const co = checkArraySorted(b.omissions, 'body.omissions', checkOmission, (f) => (f as Record<string, unknown>).path as string, 'E_DUP_PATH'); if (!co.ok) return co;
  const cte = checkArraySorted(b.testRuns, 'body.testRuns', checkTest, testIdentity, 'E_DUP_TEST'); if (!cte.ok) return cte;
  const cal = checkPathArraySortedUnique(b.rootAllowlist, 'body.rootAllowlist'); if (!cal.ok) return cal;

  // Exact partition: files.path ∪ omissions.path = rootAllowlist, files ∩ omissions = ∅ (decision 6/amendment 6).
  const filePaths = (b.files as Array<Record<string, unknown>>).map((f) => f.path as string);
  const omitPaths = (b.omissions as Array<Record<string, unknown>>).map((f) => f.path as string);
  const union = new Set([...filePaths, ...omitPaths]);
  if (union.size !== filePaths.length + omitPaths.length) return err('E_PARTITION', 'body', 'files and omissions overlap');
  const allow = new Set(b.rootAllowlist as string[]);
  if (union.size !== allow.size) return err('E_PARTITION', 'body.rootAllowlist', 'allowlist != files ∪ omissions');
  for (const pth of union) if (!allow.has(pth)) return err('E_PARTITION', 'body.rootAllowlist', `path not in allowlist: ${pth}`);

  const cli = checkString(b.limitsProfileId, 'body.limitsProfileId'); if (!cli.ok) return cli;
  const profile = LIMITS_PROFILES[b.limitsProfileId as string];
  if (!profile) return err('E_LIMIT_PROFILE', 'body.limitsProfileId', 'unknown limits profile');
  if ((b.rootAllowlist as string[]).length > profile.maxFiles) return err('E_LIMIT_FILES', 'body.rootAllowlist', 'rootAllowlist exceeds maxFiles'); // D2 amendment 3

  const cbt2 = checkStringMap(b.builderToolVersions, 'body.builderToolVersions'); if (!cbt2.ok) return cbt2;
  const cci = checkHex(b.catalogueId, SHA256_RE, 'E_BAD_SHA', 'body.catalogueId'); if (!cci.ok) return cci;
  if (b.catalogueId !== catalogueId()) return err('E_CATALOGUE_ID', 'body.catalogueId', 'catalogueId not bound to the library catalogue');

  const files = b.files as Array<Record<string, unknown>>;
  if (files.length > profile.maxFiles) return err('E_LIMIT_FILES', 'body.files', 'exceeds maxFiles');
  for (let i = 0; i < files.length; i++) {
    if ((files[i].includedByteEnd as number) - (files[i].includedByteStart as number) > profile.maxFileBytes) return err('E_LIMIT_FILE_BYTES', `body.files[${i}]`, 'included bytes exceed maxFileBytes');
  }
  if (canonicalBytes(b).length > profile.maxPackBytes) return err('E_LIMIT_PACK_BYTES', 'body', 'canonical size exceeds maxPackBytes');
  return OK;
}

export function validateEnvelope(x: unknown): ValidationResult {
  const c = closedObject(x, ['body', 'packDigest'], 'envelope'); if (!c.ok) return c;
  const e = x as Record<string, unknown>;
  const vb = validatePackBody(e.body); if (!vb.ok) return vb;
  const cd = checkHex(e.packDigest, SHA256_RE, 'E_BAD_SHA', 'envelope.packDigest'); if (!cd.ok) return cd;
  if (e.packDigest !== packDigest(e.body)) return err('E_DIGEST_MISMATCH', 'envelope.packDigest', 'digest echo mismatch');
  return OK;
}

export { AUTHORITY_KEY_RE, testIdentity };
