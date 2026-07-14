// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * Recursive, fail-closed, positive-allow-list validator (Round-11 settled contract). Unknown fields
 * are rejected at every depth including inside arrays. Authority screening applies to object KEYS only
 * — never to string content — so reviewed source may freely discuss signatures, tokens, or grants.
 * Pure: no I/O. Enforces: relative-POSIX + NFC paths, no raw NUL, lowercase exact hashes, safe
 * integers, base commit/tree pairing, closed omission-reason enum, registered limits profile, secret-
 * shaped included content refusal, content-length vs byte range, length-framed unique test identity,
 * bound catalogueId, and aggregate limits.
 */
import { EVIDENCE_PACK_SCHEMA, EvidenceErrorCode, ValidationResult, OMISSION_REASONS, LIMITS_PROFILES } from './types';
import { canonicalBytes } from './canonical';
import { packDigest } from './digest';
import { catalogueId, scanForSecrets } from './catalogue';

const SHA256_RE = /^[0-9a-f]{64}$/;
const GITSHA_RE = /^[0-9a-f]{40}$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const AUTHORITY_KEY_RE = /(?:^|[_-])(?:sign|signed|signature|grant|grants|authoriz\w*|token|apply|seed|privatekey|mutate|approve|unlock)(?:[_-]|$)/i;

const PACK_KEYS = ['schema', 'advisoryOnly', 'grantsAuthority', 'repoId', 'headCommit', 'headTree', 'baseCommit', 'baseTree', 'files', 'omissions', 'testRuns', 'rootAllowlist', 'limitsProfileId', 'builderToolVersions', 'catalogueId'];
const FILE_KEYS = ['path', 'kind', 'originalSizeBytes', 'includedByteStart', 'includedByteEnd', 'truncated', 'sha256', 'encoding', 'content'];
const OMISSION_KEYS = ['path', 'reason', 'originalSizeBytes', 'sha256'];
const TEST_KEYS = ['command', 'cwdRelative', 'exitCode', 'stdoutSha256', 'stderrSha256', 'stdoutBytes', 'stderrBytes', 'stdoutExcerpt', 'durationMs', 'toolVersions'];

const encoder = new TextEncoder();
const OK: ValidationResult = { ok: true };
function err(code: EvidenceErrorCode, path: string, message: string): ValidationResult {
  return { ok: false, code, path, message };
}
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xDC00 && n <= 0xDFFF)) return true;
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) { return true; }
  }
  return false;
}
function safeIntGE0(v: unknown): v is number { return typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0; }
function safeInt(v: unknown): v is number { return typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0); }
function utf8Len(s: string): number { return encoder.encode(s).length; }
function base64DecodedLen(s: string): number | null {
  if (s.length % 4 !== 0 || !BASE64_RE.test(s)) return null;
  if (s.length === 0) return 0;
  let pad = 0;
  if (s.charAt(s.length - 1) === '=') pad++;
  if (s.charAt(s.length - 2) === '=') pad++;
  return (s.length / 4) * 3 - pad;
}

function checkString(v: unknown, p: string): ValidationResult {
  if (typeof v !== 'string') return err('E_WRONG_TYPE', p, 'expected string');
  if (v.indexOf('\u0000') !== -1) return err('E_NUL', p, 'raw NUL in string');
  if (hasLoneSurrogate(v)) return err('E_INVALID_UTF8', p, 'lone surrogate');
  return OK;
}
function checkRelPosixPath(v: unknown, p: string): ValidationResult {
  const s = checkString(v, p);
  if (!s.ok) return s;
  const str = v as string;
  if (str.normalize('NFC') !== str) return err('E_NOT_NFC', p, 'path not NFC-normalized');
  if (str.length === 0 || str.charAt(0) === '/' || str.indexOf('\\') !== -1 || /(?:^|\/)\.\.(?:\/|$)/.test(str) || /^[A-Za-z]:/.test(str)) {
    return err('E_REL_PATH', p, 'not a relative POSIX path');
  }
  return OK;
}
function checkHex(v: unknown, re: RegExp, code: EvidenceErrorCode, p: string): ValidationResult {
  const s = checkString(v, p);
  if (!s.ok) return s;
  if (!re.test(v as string)) return err(code, p, `bad format at ${p}`);
  return OK;
}
function closedObject(v: unknown, keys: readonly string[], p: string): ValidationResult {
  if (!isPlainObject(v)) return err('E_NOT_OBJECT', p, 'expected object');
  for (const k of Object.keys(v)) if (keys.indexOf(k) === -1) return err('E_UNKNOWN_FIELD', `${p}.${k}`, `unknown field ${k}`);
  for (const k of keys) if (!(k in v)) return err('E_MISSING_FIELD', `${p}.${k}`, `missing field ${k}`);
  return OK;
}
function checkStringMap(v: unknown, p: string): ValidationResult {
  if (!isPlainObject(v)) return err('E_NOT_OBJECT', p, 'expected object');
  for (const k of Object.keys(v)) {
    if (AUTHORITY_KEY_RE.test(k)) return err('E_AUTHORITY_SHAPED_KEY', `${p}.${k}`, `authority-shaped key ${k}`);
    const ck = checkString(k, `${p}.<key>`); if (!ck.ok) return ck;
    const cv = checkString((v as Record<string, unknown>)[k], `${p}.${k}`); if (!cv.ok) return cv;
  }
  return OK;
}
function checkStringArraySortedUnique(v: unknown, p: string): ValidationResult {
  if (!Array.isArray(v)) return err('E_WRONG_TYPE', p, 'expected array');
  for (let i = 0; i < v.length; i++) {
    const c = checkString(v[i], `${p}[${i}]`); if (!c.ok) return c;
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
  const cs = checkHex(o.sha256, SHA256_RE, 'E_BAD_SHA', `${p}.sha256`); if (!cs.ok) return cs;
  if (o.encoding !== 'utf8' && o.encoding !== 'base64' && o.encoding !== 'omitted') return err('E_BAD_ENUM', `${p}.encoding`, 'encoding');
  const cc = checkString(o.content, `${p}.content`); if (!cc.ok) return cc;
  const start = o.includedByteStart as number, end = o.includedByteEnd as number, orig = o.originalSizeBytes as number;
  if (!(start <= end && end <= orig)) return err('E_BAD_RANGE', p, 'byte range');
  if (o.truncated !== (start > 0 || end < orig)) return err('E_BAD_RANGE', `${p}.truncated`, 'truncated flag inconsistent');
  if (o.kind === 'binary' && o.encoding === 'utf8') return err('E_BINARY_INLINE', `${p}.encoding`, 'binary inlined as utf8');
  const included = end - start;
  const content = o.content as string;
  if (o.encoding === 'utf8') {
    if (utf8Len(content) !== included) return err('E_CONTENT_LENGTH', `${p}.content`, 'utf8 byte length != range');
    if (scanForSecrets(content).length > 0) return err('E_SECRET_CONTENT', `${p}.content`, 'secret-shaped included content');
  } else if (o.encoding === 'base64') {
    const dl = base64DecodedLen(content);
    if (dl === null || dl !== included) return err('E_CONTENT_LENGTH', `${p}.content`, 'base64 decoded length != range');
  } else {
    if (content !== '' || included !== 0) return err('E_CONTENT_LENGTH', `${p}.content`, 'omitted must be empty with zero range');
  }
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
  for (let i = 0; i < o.command.length; i++) { const cs = checkString(o.command[i], `${p}.command[${i}]`); if (!cs.ok) return cs; }
  const cw = checkString(o.cwdRelative, `${p}.cwdRelative`); if (!cw.ok) return cw;
  if (!safeInt(o.exitCode)) return err('E_BAD_INTEGER', `${p}.exitCode`, 'int');
  const so = checkHex(o.stdoutSha256, SHA256_RE, 'E_BAD_SHA', `${p}.stdoutSha256`); if (!so.ok) return so;
  const se = checkHex(o.stderrSha256, SHA256_RE, 'E_BAD_SHA', `${p}.stderrSha256`); if (!se.ok) return se;
  if (!safeIntGE0(o.stdoutBytes)) return err('E_BAD_INTEGER', `${p}.stdoutBytes`, 'int>=0');
  if (!safeIntGE0(o.stderrBytes)) return err('E_BAD_INTEGER', `${p}.stderrBytes`, 'int>=0');
  const ex = checkString(o.stdoutExcerpt, `${p}.stdoutExcerpt`); if (!ex.ok) return ex;
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

/** Length-framed injective identity for a test run (contract decision 7). */
function testIdentity(t: unknown): string {
  const o = t as Record<string, unknown>;
  const cmd = Array.isArray(o.command) ? (o.command as string[]) : [];
  const parts = cmd.map((a) => `${a.length}:${a}`).join(',');
  return `${parts}#${String(o.cwdRelative).length}:${String(o.cwdRelative)}`;
}

export function validatePackBody(x: unknown): ValidationResult {
  const c = closedObject(x, PACK_KEYS, 'body'); if (!c.ok) return c;
  const b = x as Record<string, unknown>;

  if (b.schema !== EVIDENCE_PACK_SCHEMA) return err('E_SCHEMA', 'body.schema', 'wrong schema');
  if (b.advisoryOnly !== true) return err('E_ADVISORY_LITERAL', 'body.advisoryOnly', 'must be literal true');
  if (b.grantsAuthority !== false) return err('E_ADVISORY_LITERAL', 'body.grantsAuthority', 'must be literal false');

  const cr = checkString(b.repoId, 'body.repoId'); if (!cr.ok) return cr;
  const ch = checkHex(b.headCommit, GITSHA_RE, 'E_BAD_GITSHA', 'body.headCommit'); if (!ch.ok) return ch;
  const ct = checkHex(b.headTree, GITSHA_RE, 'E_BAD_GITSHA', 'body.headTree'); if (!ct.ok) return ct;
  // base commit/tree: both null, or both valid git shas (contract decision 1).
  const baseNull = b.baseCommit === null && b.baseTree === null;
  if (!baseNull) {
    if (b.baseCommit === null || b.baseTree === null) return err('E_BASE_PAIR', 'body.base', 'baseCommit and baseTree must both be present or both null');
    const cbc = checkHex(b.baseCommit, GITSHA_RE, 'E_BAD_GITSHA', 'body.baseCommit'); if (!cbc.ok) return cbc;
    const cbt = checkHex(b.baseTree, GITSHA_RE, 'E_BAD_GITSHA', 'body.baseTree'); if (!cbt.ok) return cbt;
  }

  const cf = checkArraySorted(b.files, 'body.files', checkFile, (f) => (f as Record<string, unknown>).path as string, 'E_DUP_PATH'); if (!cf.ok) return cf;
  const co = checkArraySorted(b.omissions, 'body.omissions', checkOmission, (f) => (f as Record<string, unknown>).path as string, 'E_DUP_PATH'); if (!co.ok) return co;
  const filePaths = new Set((b.files as Array<Record<string, unknown>>).map((f) => f.path as string));
  for (const om of b.omissions as Array<Record<string, unknown>>) {
    if (filePaths.has(om.path as string)) return err('E_DUP_PATH', 'body.omissions', `path in files and omissions: ${String(om.path)}`);
  }

  const cte = checkArraySorted(b.testRuns, 'body.testRuns', checkTest, testIdentity, 'E_DUP_TEST'); if (!cte.ok) return cte;
  const cal = checkStringArraySortedUnique(b.rootAllowlist, 'body.rootAllowlist'); if (!cal.ok) return cal;

  const cli = checkString(b.limitsProfileId, 'body.limitsProfileId'); if (!cli.ok) return cli;
  const profile = LIMITS_PROFILES[b.limitsProfileId as string];
  if (!profile) return err('E_LIMIT_PROFILE', 'body.limitsProfileId', 'unknown limits profile');

  const cbt2 = checkStringMap(b.builderToolVersions, 'body.builderToolVersions'); if (!cbt2.ok) return cbt2;
  const cci = checkHex(b.catalogueId, SHA256_RE, 'E_BAD_SHA', 'body.catalogueId'); if (!cci.ok) return cci;
  if (b.catalogueId !== catalogueId()) return err('E_CATALOGUE_ID', 'body.catalogueId', 'catalogueId not bound to the library catalogue');

  // Aggregate limits from the REGISTERED profile — never self-declared (contract decision 6).
  const files = b.files as Array<Record<string, unknown>>;
  if (files.length > profile.maxFiles) return err('E_LIMIT_FILES', 'body.files', 'exceeds maxFiles');
  for (let i = 0; i < files.length; i++) {
    if ((files[i].includedByteEnd as number) - (files[i].includedByteStart as number) > profile.maxFileBytes) return err('E_LIMIT_FILE_BYTES', `body.files[${i}]`, 'included bytes exceed maxFileBytes');
  }
  if (canonicalBytes(b).length > profile.maxPackBytes) return err('E_LIMIT_PACK_BYTES', 'body', 'canonical size exceeds maxPackBytes');

  return OK;
}

/** Full envelope validation: closed { body, packDigest } + body validity + digest echo. */
export function validateEnvelope(x: unknown): ValidationResult {
  const c = closedObject(x, ['body', 'packDigest'], 'envelope'); if (!c.ok) return c;
  const e = x as Record<string, unknown>;
  const vb = validatePackBody(e.body); if (!vb.ok) return vb;
  const cd = checkHex(e.packDigest, SHA256_RE, 'E_BAD_SHA', 'envelope.packDigest'); if (!cd.ok) return cd;
  if (e.packDigest !== packDigest(e.body)) return err('E_DIGEST_MISMATCH', 'envelope.packDigest', 'digest echo mismatch');
  return OK;
}

export { AUTHORITY_KEY_RE, testIdentity };
