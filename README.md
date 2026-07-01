# Aukora FU — Fusion Under-the-Hood (observer room)

**FU = Fusion / Fusion Under-the-Hood.** A local, read-only **observer room** that visualizes Fusion
Council / perceiver state — a consensus banner, per-model votes, a KL-divergence matrix, and a resonator
visualizer. It is a *window*, not a lever.

## What it is (and is not)
- ✅ Observer / dashboard surface. Advisory / **evidence-only**.
- ✅ Loopback-only (`127.0.0.1:9900`). Static page; no network egress, no microphone, no camera.
- ❌ NOT a kernel organ. It does **not** live in `core/src` and imports **nothing** from the kernel.
- ❌ It never signs, unlocks, promotes, authorizes, writes memory, or affects a gate verdict.

The governance boundary is non-negotiable: FU can *show* Fusion/council/perceiver state as advisory
evidence; it can never *act*. While FU lives in the seed, `core/tests/seedRootContract.test.ts` pins it as
observer-only (drift fails the gate); see `docs/SEED_ROOT_CONTRACT.md` for the serve/observer rules.

## Run
    bun run server.ts
    # → http://127.0.0.1:9900   (local, observer-only)

## Destined to be its own public repo (a gift)
FU is developed here for now but is meant to be **extracted into its own public GitHub repository** as a
gift. The whole lane is self-contained under `dashboard/fu/`, so extraction is a copy — or a clean split:

    git subtree split --prefix=dashboard/fu -b aukora-fu
    # then push branch `aukora-fu` to the new public repo

Before going public: add a LICENSE (owner's choice), keep the observer-only invariants (no authority, no
live secrets, loopback-only, advisory evidence only), and wire any live data as READ-ONLY evidence (e.g.
the seed's `fusion-advisory-v1` artifact) — never a control surface.
