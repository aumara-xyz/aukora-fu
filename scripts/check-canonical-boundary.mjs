import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const srcDir = path.join(root, 'src');
const forbiddenImport = /(?:authority(?:\/|$)|convex|aumlok|nativeLiveApply|(?:^|\/)memory(?:\/|$)|aura|kira|policyKernel|signer|voiceLane|opencode\/auth|symbiotePaths)/i;
const failures = [];

for (const name of fs.readdirSync(srcDir).filter((file) => file.endsWith('.ts'))) {
  const file = path.join(srcDir, name);
  const source = fs.readFileSync(file, 'utf8');
  for (const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) {
    if (forbiddenImport.test(match[1])) failures.push(`${name}: forbidden import ${match[1]}`);
  }
}

for (const name of ['aukoraFuGlyph.ts', 'aukoraFuCouncil.ts']) {
  const source = fs.readFileSync(path.join(srcDir, name), 'utf8');
  const code = source.split('\n').filter((line) => !line.trim().startsWith('//') && !line.trim().startsWith('*')).join('\n');
  for (const [label, pattern] of [
    ['network', /\bfetch\s*\(/],
    ['environment', /process\.env/],
    ['filesystem', /(?:node:fs|from\s+['"]fs['"])/],
    ['ambient capture', /fusionCaptureLog|\.aukora-symbiote/],
  ]) {
    if (pattern.test(code)) failures.push(`${name}: forbidden ${label} capability`);
  }
}

if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('canonical Fu boundary: clean');
