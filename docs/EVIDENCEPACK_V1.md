<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (c) 2026 Aukora -->

# EvidencePack v1 — contract (Round-11 settled)

> The pure, offline, deterministic evidence boundary for Aukora Fu. It carries **evidence**, never
> authority. `advisoryOnly: true` and `grantsAuthority: false` are literal, validator-enforced
> invariants. This document is the byte-level source of truth; the implementation (`src/evidence/`)
> agrees with it field-for-field. **Commit 1 is pure** — no filesystem, network, environment,
> subprocess, transport, observer, spend, signing, apply, or repository mutation. The filesystem
> reader (Commit 2) is not part of this.

## 1. Law
The Seed has hands to heal, but no authority to forge. A green pack proves *what was presented and
that it is internally consistent* — it does **not** prove disk fidelity, provider honesty, or that
`testRuns[]` output came from a real command (§13).

## 2. Body vs. envelope
`EvidencePackV1` is the reproducible **body** (no digest field). `EvidencePackEnvelopeV1 = { body,
packDigest }`. Every body field participates in `packDigest`; `packDigest` does not. **No timestamp
lives in the pack** (decision 3) — a later controller-run artifact may bind `createdAtIso` alongside
`packDigest`.

## 3. Subject (snapshot-primary, decision 1)
`repoId`, `headCommit` (40-hex), `headTree` (40-hex). Optional comparison: `baseCommit` + `baseTree`
— **both** present or **both** `null` (`E_BASE_PAIR`). There is **no** `diffSha256` — a diff may only
be carried later as exact bound diff bytes.

## 4. Evidence (decision 2)
`testRuns[]` is the evidence: `command[]`, `cwdRelative`, `exitCode`, `stdoutSha256`, `stderrSha256`,
`stdoutBytes`, `stderrBytes`, `stdoutExcerpt`, `durationMs|null`, `toolVersions`. **Narrative
`claims[]` are excluded** from EvidencePack (they belong in a separate Fu advisory artifact).

## 5. Files / omissions
`files[]`: `path` (relative POSIX, NFC), `kind` (`text|binary`), `originalSizeBytes`,
`includedByteStart`, `includedByteEnd`, `truncated`, `sha256` (over the full original bytes), `encoding`
(`utf8|base64|omitted`), `content`. `omissions[]`: `path`, `reason` (**closed enum**, decision 10),
`originalSizeBytes|null`, `sha256|null`. A path is in `files` XOR `omissions`. Both arrays sort by NFC
`path`.

## 6. Canonicalization (JCS-aligned)
Minified UTF-8 JSON, LF, no insignificant whitespace. Object keys sorted by UTF-16 code unit; arrays
preserved in given order; numbers are finite safe integers emitted without exponent (`-0`→`0`);
strings via JSON escaping.

## 7. Digest — domain-separated + length-framed
`packDigest = hex( SHA-256( utf8("aukora-fu-evidence-pack-v1") ‖ 0x00 ‖ uint64BE(len(C)) ‖ C ) )`,
`C = canonicalBytes(body)`. Lowercase 64-hex.

## 8. Fence (decision 4 — derived, never stored)
The inert-data fence is derived at presentation from `(domain, packDigest, counter)`, incrementing the
counter until neither `<<AUKORA-DATA:nonce>>` nor `<<AUKORA-END:nonce>>` occurs in any content. It is
**not** a stored body field, so the reproducible body carries no presentation state.

## 9. Catalogue (decision 5)
`catalogueId` (bound body field) must equal `SHA-256(canonicalBytes(SECRET_CATALOGUE))`. Any catalogue
change changes the id. The catalogue is used to **refuse** (never redact-and-retain) any pack whose
included text content is secret-shaped (decision 10, `E_SECRET_CONTENT`).

## 10. Limits (decision 6 — registry-owned)
`limitsProfileId` names a registered immutable profile (`LIMITS_PROFILES`); the validator uses that
profile's `maxFileBytes`/`maxPackBytes`/`maxFiles`. A pack **cannot self-declare** ceilings; a self-
declared `limits` object is an unknown field.

## 11. Test identity (decision 7)
Ordering/dedup key length-frames every argv element and the cwd:
`argv.map(a => len(a)+":"+a).join(",") + "#" + len(cwd)+":"+cwd`. `["a b"]` ≠ `["a","b"]`. Duplicate
identities are rejected (`E_DUP_TEST`).

## 12. Validation invariants (decisions 8, 9, 12, 13)
Recursive closed schema — unknown fields rejected at every depth. Authority-shaped keys rejected on
object **keys only**, never on content (`E_AUTHORITY_SHAPED_KEY`). Relative POSIX + NFC paths
(`E_REL_PATH`/`E_NOT_NFC`); **no raw NUL** in any string (`E_NUL`); lone-surrogate rejection; lowercase
exact `sha256`/git-sha; safe integers; content length vs. byte range verified for utf8/base64/omitted
(`E_CONTENT_LENGTH`); aggregate limits (§10). The pack contains **no** signature, approval, token,
grant, apply, signing, mutation, or authorization field.

## 13. Honest limitations
A pure pack cannot prove disk fidelity, provider honesty, or real command execution. It proves
internal consistency, tamper-evidence, catalogue binding, content/range agreement, limit compliance,
and secret-free included content — nothing more.

## 14. Known-answer vectors (decision 11)
Fixed, independently recomputable vectors are pinned in `test/evidencePackV1.test.ts` and reproduced by
`scripts/pyref/evidence_canonical_ref.py` (Python) and under Node + Bun: the minimal-body canonical
bytes, its `packDigest` (`508d4349…`), the `catalogueId` (`04b0ae21…`, catalogue v2), a maximal-body
`packDigest` (`6e8f4360…`), and a fence nonce (`3a23cb4c…a706ccf9…` (full 64-hex) for `deriveFenceNonce("00"×32,
["hello","world"])`).

## Round-12 (Commit D) amendments
Building on the settled contract, Commit D adds:
- **File hashes:** `sha256` → `fullSha256` (full original bytes) + `includedSha256` (recomputed from the
  **decoded** included content); a complete file (`start=0`, `end=originalSize`) requires
  `includedSha256 === fullSha256`.
- **No `encoding:"omitted"`** on files; excluded entries live only in `omissions[]`. `text`⇒`utf8`,
  `binary`⇒`base64` with a **canonical base64 round-trip**.
- **Exact partition:** `files.path ∪ omissions.path = rootAllowlist`, `files.path ∩ omissions.path = ∅`.
- **Path discipline everywhere:** relative-POSIX + NFC for file/omission/allowlist paths and test `cwd`
  (`"."` allowed only for `cwd`). **No raw NUL** in any string.
- **Secret projections** (raw, NFC, zero-width-stripped, confusable-skeleton) applied to utf8 content,
  base64-decoded-as-text, and `stdoutExcerpt`/`stderrExcerpt`; any hit **refuses** the pack.
- **Open maps:** keys must match `^[A-Za-z0-9][A-Za-z0-9._-]*$`; values must be NFC.
- **Test identity** length-frames every argv element and cwd by **UTF-8 byte length**; argv NFC-asserted.
- **Canonicalizer rejects `-0`** outright (decision 14). **Strict canonical-wire verification**
  (`verifyCanonicalWire`) rejects BOM, leading/trailing/alternate whitespace, duplicate keys, alternate
  numeric/escape encodings, and malformed Unicode (decision 15).

## Round-13 (D1) amendments
- **Full-width fence:** `deriveFenceNonce` uses the entire 64-hex SHA-256 (no truncation).
- **Exact base64 secret scan:** for `base64` file content, always scan a deterministic ASCII-byte
  projection (printable ASCII + TAB/LF/CR retained; every other byte → LF), which catches an ASCII
  secret hidden inside invalid-UTF-8 binary; additionally strict-decode UTF-8
  (`TextDecoder("utf-8",{fatal:true})`) and, on success, run the raw/NFC/zero-width/confusable
  projections, which catches a confusable secret inside valid-UTF-8 base64.

## Error taxonomy
`E_SCHEMA, E_NOT_OBJECT, E_MISSING_FIELD, E_UNKNOWN_FIELD, E_WRONG_TYPE, E_ADVISORY_LITERAL,
E_AUTHORITY_SHAPED_KEY, E_NOT_NFC, E_REL_PATH, E_NUL, E_INVALID_UTF8, E_BAD_INTEGER, E_BAD_SHA,
E_BAD_GITSHA, E_BASE_PAIR, E_ARRAY_UNSORTED, E_DUP_PATH, E_DUP_TEST, E_BAD_RANGE, E_BINARY_INLINE,
E_BAD_ENUM, E_CONTENT_LENGTH, E_SECRET_CONTENT, E_OMISSION_REASON, E_LIMIT_PROFILE, E_LIMIT_FILES,
E_LIMIT_FILE_BYTES, E_LIMIT_PACK_BYTES, E_CATALOGUE_ID, E_DIGEST_MISMATCH, E_HASH_INCLUDED,
E_HASH_COMPLETE, E_BASE64_NONCANONICAL, E_PARTITION, E_MAP_KEY, E_MAP_VALUE_NFC, E_CWD`.
