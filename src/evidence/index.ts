// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * EvidencePack v1 — pure public surface. No filesystem, environment, network, subprocess, transport,
 * observers, council wiring, spend, UI, signing, or authority. See docs/EVIDENCEPACK_V1.md.
 */
export * from './types';
export { canonicalString, canonicalBytes, verifyCanonicalWire } from './canonical';
export { packDigest, packDigestOfCanonical, sha256Hex, uint64BE, DIGEST_DOMAIN } from './digest';
export { deriveFenceNonce, fence, fenceOpen, fenceClose, fenceCollisionFree, FENCE_DOMAIN } from './framing';
export { SECRET_CATALOGUE, catalogueId, scanForSecrets, secretProjections, textHasSecret } from './catalogue';
export { validatePackBody, validateEnvelope, AUTHORITY_KEY_RE, testIdentity } from './validate';

import { EvidencePackV1, EvidencePackEnvelopeV1 } from './types';
import { canonicalBytes, canonicalString } from './canonical';
import { packDigest } from './digest';
import { validatePackBody, validateEnvelope } from './validate';

/** Recursively freeze an accepted, canonical-cloned value so a sealed envelope cannot be mutated. */
function deepFreeze<T>(o: T): T {
  if (o !== null && typeof o === 'object') {
    for (const k of Object.keys(o as Record<string, unknown>)) deepFreeze((o as Record<string, unknown>)[k]);
    Object.freeze(o);
  }
  return o;
}

/**
 * Validate a body then seal it. D2 (amendment 6): the accepted body is canonical-cloned (ordinary
 * prototypes, no inherited or extra properties) and the whole envelope is recursively frozen, so evidence
 * cannot be mutated after sealing. Throws `<code>:<path>` if the body is invalid.
 */
export function sealEnvelope(body: EvidencePackV1): EvidencePackEnvelopeV1 {
  const v = validatePackBody(body);
  if (!v.ok) throw new Error(`${v.code}:${v.path}`);
  const cloned = JSON.parse(canonicalString(body)) as EvidencePackV1;
  return deepFreeze({ body: cloned, packDigest: packDigest(cloned) });
}

/** Digest-echo verification: recompute and compare. Delegates to the full envelope validator. */
export function verifyEnvelope(env: EvidencePackEnvelopeV1): boolean {
  return validateEnvelope(env).ok;
}

/**
 * Identical-seat render. D2 (amendment 7): re-validate the envelope first and REFUSE invalid or
 * post-seal-mutated evidence, so a mutated body can never be rendered to a seat. The serialized bytes are
 * identical for every seat — no seat-specific data enters the pack.
 */
export function renderForSeat(env: EvidencePackEnvelopeV1, seatId: string): Uint8Array {
  // Take ONE canonical snapshot up front, then validate and serialize the SAME snapshot — so an accessor
  // (getter) that returns different values on successive reads cannot pass validation clean yet render dirty.
  const snap = JSON.parse(canonicalString(env)) as EvidencePackEnvelopeV1;
  const v = validateEnvelope(snap);
  if (!v.ok) throw new Error(`${v.code}:${v.path}`);
  void seatId;
  return canonicalBytes(snap);
}
