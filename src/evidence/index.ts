// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * EvidencePack v1 — pure public surface. No filesystem, environment, network, subprocess, transport,
 * observers, council wiring, spend, UI, signing, or authority. See docs/EVIDENCEPACK_V1.md.
 */
export * from './types';
export { canonicalString, canonicalBytes } from './canonical';
export { packDigest, packDigestOfCanonical, sha256Hex, uint64BE, DIGEST_DOMAIN } from './digest';
export { deriveFenceNonce, fence, fenceOpen, fenceClose, fenceCollisionFree } from './framing';
export { SECRET_CATALOGUE, catalogueId, scanForSecrets } from './catalogue';
export { validatePackBody, validateEnvelope, AUTHORITY_KEY_RE } from './validate';

import { EvidencePackV1, EvidencePackEnvelopeV1 } from './types';
import { canonicalBytes } from './canonical';
import { packDigest } from './digest';
import { validatePackBody, validateEnvelope } from './validate';

/** Validate a body then seal it into an envelope. Throws `<code>:<path>` if the body is invalid. */
export function sealEnvelope(body: EvidencePackV1): EvidencePackEnvelopeV1 {
  const v = validatePackBody(body);
  if (!v.ok) throw new Error(`${v.code}:${v.path}`);
  return { body, packDigest: packDigest(body) };
}

/** Digest-echo verification: recompute and compare. Delegates to the full envelope validator. */
export function verifyEnvelope(env: EvidencePackEnvelopeV1): boolean {
  return validateEnvelope(env).ok;
}

/** Identical-seat render: the serialized bytes are the same for every seat — no seat-specific data
 *  enters the pack, so the seatId argument can never change the output. */
export function renderForSeat(env: EvidencePackEnvelopeV1, seatId: string): Uint8Array {
  void seatId;
  return canonicalBytes(env);
}
