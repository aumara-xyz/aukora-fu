# Aukora FU — Fusion Under-the-Hood

**FU = Fusion / Fusion Under-the-Hood.** This private repository is becoming the canonical home of
Aukora's advisory multi-model council. The hardened offline core now lives in `src/`; the original
standalone shard runner and browser observer remain available as explicitly legacy surfaces while the
canonical EvidencePack, transport, observer, and CLI layers are built in reviewed commits.

## What it is (and is not)
- ✅ Hardened advisory council core with offline tests: `npm run verify`.
- ⚠️ Legacy local shard runner: `bun run council` (prints a legacy warning).
- ✅ Browser observer: `bun run start` then open `http://127.0.0.1:9900`.
- ✅ Demo/sample mode with no API key: `bun run sample`.
- ✅ Loopback-only UI (`127.0.0.1:9900`). No microphone, no camera.
- ✅ **Read-only server**: writes nothing, deletes nothing, runs no tool; guards path traversal to `runs/`.
- ❌ NOT a kernel organ. It does **not** live in `core/src` and imports **nothing** from the kernel.
- ❌ It never signs, unlocks, promotes, authorizes, writes memory, or affects a gate verdict.

The governance boundary is non-negotiable: FU can review and visualize. It cannot authorize. The
canonical core is being extracted here once from the provenance-pinned Symbiote donor. After a reviewed
Fu release exists, Symbiote will consume that pinned release instead of maintaining a second copy.

## Canonical save-point status

- Canonical now: council orchestration, glyph parsing/perception, quorum, phase-lock analysis, neutral
  replay, reserve/reconcile spend meter, append-only spend ledger, and offline conformance tests.
- Still legacy: `run-council.ts`, its raw folder scraper, `fusion-run-v1`, and the current dashboard flow.
- Not built yet: EvidencePackV1, hardened OpenRouter/Fugu observers, canonical CLI, public package, and
  Symbiote adapter.
- Provenance: [`docs/provenance/SYMBIOTE_EXTRACTION_2026-07-14.md`](docs/provenance/SYMBIOTE_EXTRACTION_2026-07-14.md).

## Quick Start

1. Install Bun:

       https://bun.sh

2. Install and verify the hardened offline core:

       bun install --frozen-lockfile
       npm run verify

3. Start the legacy browser observer:

       bun run start

4. Open:

       http://127.0.0.1:9900

5. In a second terminal, prove the legacy runner writes a sample run:

       bun run sample

6. The legacy paid runner is retained for compatibility, but must not be treated as the canonical
   hardened review path. No new paid run should be made until observer accounting and EvidencePackV1 land.

       cp .env.example .env
       # edit .env and set OPENROUTER_API_KEY
       bun run legacy:council

The page refreshes when a new run lands. Generated `runs/*.json` are local output and are gitignored.

## Review Another Folder

The following command belongs to the legacy raw-folder runner. It is not the future EvidencePackV1
interface and must not be used on a directory containing secrets or private material:

    FUSION_TARGET=/absolute/path/to/project COUNCIL_BUDGET=10 bun run council

Useful knobs:

    COUNCIL_BUDGET=10          # max model calls
    COUNCIL_CONCURRENCY=3      # max simultaneous calls, clamped 1..8
    FUSION_MODELS=a,b,c        # comma-separated OpenRouter model slugs

Endpoints (all read-only): `/api/runs`, `/api/run/latest`, `/api/run/:id`, and SSE `/api/stream`
(live-refresh when a new run lands).

## Private Lab Warning

This is private early tech. Do not publish without a release/legal/provenance review. Do not commit
`.env` or generated `runs/*.json`. No license, visibility, release, or trademark decision is implied by
the canonical-core extraction.
