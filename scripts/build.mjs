#!/usr/bin/env node
// Deterministic build: clean dist/, compile TypeScript, copy static assets, mark the CLI executable.
import { execFileSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');
const require = createRequire(import.meta.url);

rmSync(dist, { recursive: true, force: true });
execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', join(root, 'tsconfig.build.json')], {
  stdio: 'inherit',
  cwd: root,
});

const copies = [
  ['src/admin/static', 'dist/admin/static'],
  ['tests/fixtures/course', 'dist/fixtures/course'],
];
for (const [from, to] of copies) {
  cpSync(join(root, from), join(root, to), { recursive: true, filter: (src) => !src.endsWith('.DS_Store') });
}

const cli = join(dist, 'cli', 'main.js');
if (!existsSync(cli) || !readFileSync(cli, 'utf8').startsWith('#!/usr/bin/env node')) {
  throw new Error('dist/cli/main.js is missing or lacks a node shebang');
}
chmodSync(cli, 0o755);
console.log('build complete');
