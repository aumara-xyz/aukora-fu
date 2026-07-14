# Aukora Fu canonical-core extraction — 2026-07-14

This private save point records the one-time extraction of the hardened advisory council from Aukora
Symbiote into the existing `aumara-xyz/aukora-fu` repository. It does not change repository visibility,
licensing, authority semantics, or release status.

## Source pins

- Donor repository: `aumara-xyz/aukora-symbiote`
- Donor commit: `41707f910d10696482c28ee80346c252a55e9d41`
- Donor tree: `7020cc0230fad3dd793d7ae6a50ddf05f6e3eac4`
- Target base: `aumara-xyz/aukora-fu@5a98e44e7917a576868b51ebd22a50f52446cc66`
- Target base tree: `7ab6e9b23e5ca1672a7082c925152a56cd26ec5c`

## Extracted source evidence

| Donor path | Git blob | SHA-256 of donor bytes |
|---|---|---|
| `core/src/aukoraFuCouncil.ts` | `b34b6a0cf3b7f5fefe29c1bc993587a0c27266cf` | `0f2f6b2e0d7df479b18c135d8b35437d0727875fd6c03d3568c4463ee2b61663` |
| `core/src/aukoraFuEngine.ts` | `4239132de10d0e88d157ae1f2526861adf84f9a8` | `5b68d0f409697c83f4d076ec7cb71eea344275879711471898451a7e1dafbb3a` |
| `core/src/aukoraFuSpendLedger.ts` | `60d4407cf4ad8056802e3dbb3be7fd88a0ecec60` | `1b9935a0eb1c4e254638281a5a4197cc627d9764e1f6f57c9663a6ba5d5a04d3` |
| `core/tests/aukoraFuCouncil.test.ts` | `7a8169fd6d3980660c2f65030626c2aaceff2c44` | `084e602884197ddc4b79a41544e67cf9d01d12c44ee5caa3ad9212eac52e6f5d` |
| `core/tests/aukoraFuEngine.test.ts` | `2742e56d7a3092e7db12ffc1ca5c4b4d965422a1` | `5174b7180f50dfb3c61b916867aeb63887dd8a4baa1cd721c8cb5065d48a0978` |
| `core/tests/aukoraFuSpendLedger.test.ts` | `99bff7fd48b720b2bdf341463dfbd4d862e94417` | `08badddc16621d3531eb586ecff94a11b2333d8a7edaad6570e3453c531e1d4b` |

The real captured reply fixtures under `core/tests/fixtures/fusion-replies/` were also extracted as
test evidence. They contain model output only and no credentials or authority material.

## Deliberate boundary changes

1. The donor `aukoraFuEngine.ts` was narrowed to `aukoraFuGlyph.ts`: only its pure glyph vocabulary,
   parser, interference geometry, and perceiver primitives were retained. Its older direct-network
   engine and `fusionCaptureLog`/`authority/symbiotePaths` edge were excluded entirely.
2. The standalone caller-set test recognizes only the canonical council. Symbiote's
   `selfEditReviewCouncil.ts` is not copied.
3. The pre-existing standalone `run-council.ts` remains operational but is explicitly labeled legacy.
4. No observer adapter, API-key discovery, Symbiote path convention, memory, AURA, custody, signing,
   Convex, live apply, or private OS/lab source is included.
5. No paid model call is part of this save point.

## Authority boundary

All council outputs are advisory evidence. They are pinned `advisoryOnly: true` and
`grantsAuthority: false`. Aukora Fu cannot sign, authorize, apply, write memory, or mutate a reviewed
repository. EvidencePackV1, hardened observers, the canonical CLI, and Symbiote package consumption are
future reviewed commits, not part of this extraction.
