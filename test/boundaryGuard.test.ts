import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const roots: string[] = [];
const guard = path.resolve('scripts/check-canonical-boundary.mjs');

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function runGuard(files: Record<string, string>) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aukora-fu-boundary-'));
  roots.push(root);
  for (const [name, source] of Object.entries(files)) {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, source);
  }
  return spawnSync(process.execPath, [guard, '--src', root, '--quiet'], { encoding: 'utf8' });
}

describe('canonical Fu boundary guard', () => {
  it('recursively accepts an inert nested module', () => {
    const result = runGuard({ 'nested/safe.ts': 'export const advisoryOnly = true;\n' });
    expect(result.status, result.stderr).toBe(0);
  });

  it('rejects a nested network call', () => {
    const result = runGuard({ 'nested/network.ts': 'export async function call() { return fetch("https://example.test"); }\n' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('forbidden network capability fetch');
  });

  it('rejects a dynamic authority import', () => {
    const result = runGuard({ 'nested/authority.ts': 'export const load = () => import("../aumlokSigner");\n' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('forbidden import ../aumlokSigner');
  });

  it('rejects side-effect and CommonJS imports', () => {
    const sideEffect = runGuard({ 'side-effect.ts': 'import "convex/server";\n' });
    const commonJs = runGuard({ 'commonjs.ts': 'const signer = require("./aumlok/signer");\n' });
    expect(sideEffect.status).toBe(1);
    expect(sideEffect.stderr).toContain('forbidden import convex/server');
    expect(commonJs.status).toBe(1);
    expect(commonJs.stderr).toContain('forbidden import ./aumlok/signer');
  });

  it('rejects non-literal imports and environment discovery', () => {
    const dynamic = runGuard({ 'dynamic.ts': 'const target = "./safe"; export const load = () => import(target);\n' });
    const environment = runGuard({ 'env.ts': 'export const key = process.env.OPENROUTER_API_KEY;\n' });
    expect(dynamic.status).toBe(1);
    expect(dynamic.stderr).toContain('non-literal dynamic import is forbidden');
    expect(environment.status).toBe(1);
    expect(environment.stderr).toContain('forbidden environment capability');
  });

  it('rejects captured network globals and effect modules', () => {
    const captured = runGuard({ 'captured.ts': 'const network = fetch; export { network };\n' });
    const effect = runGuard({ 'effect.ts': 'import { execFile } from "node:child_process"; export { execFile };\n' });
    expect(captured.status).toBe(1);
    expect(captured.stderr).toContain('forbidden network capability fetch');
    expect(effect.status).toBe(1);
    expect(effect.stderr).toContain('forbidden effect module node:child_process');
  });

  it('allows filesystem access only in the root spend-ledger module', () => {
    const denied = runGuard({ 'nested/read.ts': 'import fs from "node:fs"; export const read = fs.readFileSync;\n' });
    const allowed = runGuard({ 'aukoraFuSpendLedger.ts': 'import fs from "node:fs"; export const read = fs.readFileSync;\n' });
    expect(denied.status).toBe(1);
    expect(denied.stderr).toContain('forbidden filesystem module node:fs');
    expect(allowed.status, allowed.stderr).toBe(0);
  });
});
