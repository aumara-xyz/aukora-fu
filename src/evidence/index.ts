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

/** Recursively freeze so a sealed envelope cannot be mutated in place after validation (D2 amendment 6). */
function deepFreeze<T>(o: T): T {
  if (o !== null && typeof o === 'object') {
    for (const k of Object.keys(o as Record<string, unknown>)) deepFreeze((o as Record<string, unknown>)[k]);
    Object.freeze(o);
  }
  return o;
}

/** Validate a body, then seal it into an envelope over a CANONICAL CLONE of the accepted evidence and
 *  recursively freeze the result (D2 amendment 6): the sealed bytes are exactly what was validated, and
 *  no later in-place mutation of the caller's original object can silently diverge from the digest.
 *  Throws `<code>:<path>` if the body is invalid. */
export function sealEnvelope(body: EvidencePackV1): EvidencePackEnvelopeV1 {
  const v = validatePackBody(body);
  if (!v.ok) throw new Error(`${v.code}:${v.path}`);
  const clone = JSON.parse(canonicalString(body)) as EvidencePackV1; // canonical clone: same bytes, fresh objects
  return deepFreeze({ body: clone, packDigest: packDigest(clone) });
}

/** Digest-echo verification: recompute and compare. Delegates to the full envelope validator. */
export function verifyEnvelope(env: EvidencePackEnvelopeV1): boolean {
  return validateEnvelope(env).ok;
}

/** Identical-seat render: the serialized bytes are the same for every seat — no seat-specific data
 *  enters the pack, so the seatId argument can never change the output. D2 amendment 7: revalidate the
 *  envelope and REFUSE anything invalid or mutated after sealing (throws `<code>:<path>`). */
export function renderForSeat(env: EvidencePackEnvelopeV1, seatId: string): Uint8Array {
  void seatId;
  const v = validateEnvelope(env);
  if (!v.ok) throw new Error(`${v.code}:${v.path}`);
  return canonicalBytes(env);
}
