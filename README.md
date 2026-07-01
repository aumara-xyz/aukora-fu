# Aukora FU — Fusion Under-the-Hood (observer room)

**FU = Fusion / Fusion Under-the-Hood.** A local, read-only **observer room** that visualizes Fusion
Council / perceiver state — a consensus banner, per-model votes, a KL-divergence matrix, and a resonator
visualizer. It is a *window*, not a lever.

## What it is (and is not)
- ✅ Observer / dashboard surface. Advisory / **evidence-only**.
- ✅ Loopback-only (`127.0.0.1:9900`). Reads validated **`fusion-run-v1`** artifacts; no network egress, no microphone, no camera.
- ✅ **Read-only server**: writes nothing, deletes nothing, runs no tool; guards path traversal to `runs/`.
- ❌ NOT a kernel organ. It does **not** live in `core/src` and imports **nothing** from the kernel.
- ❌ It never signs, unlocks, promotes, authorizes, writes memory, or affects a gate verdict.

The governance boundary is non-negotiable: FU can *show* Fusion/council/perceiver state as advisory
evidence; it can never *act*. While FU lives in the seed, `core/tests/seedRootContract.test.ts` +
`core/tests/fusionRunArtifact.test.ts` pin it as observer-only (drift fails the gate); see
`docs/SEED_ROOT_CONTRACT.md` for the serve/observer rules.

## Run
    # 1. serve the observer (read-only, loopback)
    bun run server.ts            # → http://127.0.0.1:9900
    # 2. (optional) fire a real council run — writes a validated fusion-run-v1 artifact into runs/
    cd ../../core && bun run run-council.ts   # COUNCIL_BUDGET=3 for a cheap smoke

Endpoints (all read-only): `/api/runs`, `/api/run/latest`, `/api/run/:id`, and SSE `/api/stream`
(live-refresh when a new run lands). Generated `runs/*.json` are gitignored — never commit raw council
output; ship a clearly synthetic sample under `examples/` if a public copy needs demo data.

## Destined to be its own public repo (a gift)
FU is developed here for now but is meant to be **extracted into its own public GitHub repository** as a
gift. The whole lane is self-contained under `dashboard/fu/`, so extraction is a copy — or a clean split:

    git subtree split --prefix=dashboard/fu -b aukora-fu
    # then push branch `aukora-fu` to the new public repo

Before going public: add a LICENSE (owner's choice), keep the observer-only invariants (no authority, no
live secrets, loopback-only, advisory evidence only), and wire any live data as READ-ONLY evidence (e.g.
the seed's `fusion-advisory-v1` artifact) — never a control surface.
