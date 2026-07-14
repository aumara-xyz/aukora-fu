// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aukora
/**
 * Deterministic canonical serialization (JCS-aligned per docs/EVIDENCEPACK_V1.md §5).
 * Object keys sorted ascending by UTF-16 code unit; arrays preserved as given; numbers must be finite
 * safe integers emitted without exponent/fraction (-0 normalized to 0); strings via JSON escaping;
 * UTF-8 output. Pure — no I/O.
 */

const encoder = new TextEncoder();

function encodeNumber(n: number): string {
  if (!Number.isFinite(n) || !Number.isSafeInteger(n)) {
    throw new Error('E_BAD_INTEGER');
  }
  return String(n === 0 ? 0 : n); // normalize -0 -> 0
}

export function canonicalString(value: unknown): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  const t = typeof value;
  if (t === 'number') return encodeNumber(value as number);
  if (t === 'string') return JSON.stringify(value as string);
  if (Array.isArray(value)) {
    let out = '[';
    for (let i = 0; i < value.length; i++) {
      if (i > 0) out += ',';
      out += canonicalString(value[i]);
    }
    return out + ']';
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    let out = '{';
    for (let i = 0; i < keys.length; i++) {
      if (i > 0) out += ',';
      out += JSON.stringify(keys[i]) + ':' + canonicalString(obj[keys[i]]);
    }
    return out + '}';
  }
  throw new Error('E_WRONG_TYPE');
}

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalString(value));
}
