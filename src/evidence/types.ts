// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * EvidencePack v1 — pure types and stable error codes. See docs/EVIDENCEPACK_V1.md (the frozen
 * contract). No filesystem, environment, network, subprocess, or authority. The literal fields
 * advisoryOnly:true / grantsAuthority:false are load-bearing invariants: a pack is evidence, never
 * authority.
 */

export const EVIDENCE_PACK_SCHEMA = 'aukora-fu-evidence-pack-v1';
export type EvidencePackSchema = typeof EVIDENCE_PACK_SCHEMA;

export interface EvidenceFileV1 {
  readonly path: string;
  readonly kind: 'text' | 'binary';
  readonly originalSizeBytes: number;
  readonly includedByteStart: number;
  readonly includedByteEnd: number;
  readonly truncated: boolean;
  readonly sha256: string;
  readonly encoding: 'utf8' | 'base64' | 'omitted';
  readonly content: string;
  readonly secretsRedacted: number;
}

export interface EvidenceOmissionV1 {
  readonly path: string;
  readonly reason: string;
  readonly originalSizeBytes: number | null;
  readonly sha256: string | null;
}

export interface EvidenceTestRunV1 {
  readonly command: readonly string[];
  readonly cwdRelative: string;
  readonly exitCode: number;
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutExcerpt: string;
  readonly durationMs: number | null;
  readonly toolVersions: Readonly<Record<string, string>>;
}

export interface EvidenceClaimV1 {
  readonly id: string;
  readonly text: string;
}

export interface EvidenceLimitsV1 {
  readonly maxFileBytes: number;
  readonly maxPackBytes: number;
  readonly maxFiles: number;
}

export interface EvidencePackV1 {
  readonly schema: EvidencePackSchema;
  readonly advisoryOnly: true;
  readonly grantsAuthority: false;
  readonly repo: string;
  readonly baseCommit: string;
  readonly headCommit: string;
  readonly headTree: string;
  readonly createdAtIso: string;
  readonly diffSha256: string;
  readonly files: readonly EvidenceFileV1[];
  readonly omissions: readonly EvidenceOmissionV1[];
  readonly tests: readonly EvidenceTestRunV1[];
  readonly claims: readonly EvidenceClaimV1[];
  readonly rootAllowlist: readonly string[];
  readonly limits: EvidenceLimitsV1;
  readonly builderToolVersions: Readonly<Record<string, string>>;
  readonly dataFenceNonce: string;
}

export interface EvidencePackEnvelopeV1 {
  readonly body: EvidencePackV1;
  readonly packDigest: string;
}

export const ERROR_CODES = [
  'E_SCHEMA', 'E_NOT_OBJECT', 'E_MISSING_FIELD', 'E_UNKNOWN_FIELD', 'E_WRONG_TYPE', 'E_ADVISORY_LITERAL',
  'E_AUTHORITY_SHAPED_KEY', 'E_NOT_NFC', 'E_INVALID_UTF8', 'E_BAD_INTEGER', 'E_BAD_SHA', 'E_BAD_GITSHA',
  'E_BAD_TIMESTAMP', 'E_ARRAY_UNSORTED', 'E_DUP_PATH', 'E_BAD_RANGE', 'E_BINARY_INLINE', 'E_BAD_ENUM',
  'E_BAD_HEX', 'E_DIGEST_MISMATCH',
] as const;
export type EvidenceErrorCode = typeof ERROR_CODES[number];

export interface ValidationOk { readonly ok: true; }
export interface ValidationErr {
  readonly ok: false;
  readonly code: EvidenceErrorCode;
  readonly path: string;
  readonly message: string;
}
export type ValidationResult = ValidationOk | ValidationErr;
