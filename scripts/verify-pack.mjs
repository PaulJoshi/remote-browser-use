#!/usr/bin/env node
// Publishing gate from docs/06-publishing.md: rebuild dist/, dry-run npm pack,
// and audit the tarball file list. Publishes nothing.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const pkg = require('../package.json');

// Fresh deterministic build so a standalone run cannot audit a stale dist/.
execFileSync(process.execPath, [join(root, 'scripts', 'build.mjs')], { cwd: root, stdio: 'inherit' });

// Use the npm that invoked this script (npm_execpath) so this also works on Windows.
const npmCli = process.env.npm_execpath;
const out = npmCli
  ? execFileSync(process.execPath, [npmCli, 'pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' })
  : execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' });

const jsonStart = out.search(/[[{]/);
const packed = JSON.parse(out.slice(jsonStart));
const info = Array.isArray(packed) ? packed[0] : packed;
const files = info.files.map((f) => (f.path ?? f).replace(/\\/g, '/'));

const REQUIRED = ['package.json', 'README.md', 'LICENSE', 'NOTICE', 'dist/cli/main.js', 'dist/index.js', 'dist/index.d.ts'];
const REQUIRED_PREFIXES = ['dist/admin/static/', 'dist/fixtures/course/'];
const FORBIDDEN = [
  [/^(src|tests?|docs|scripts|\.github|\.devin|\.vscode|\.idea|coverage|\.tmp|dist-check)\//, 'development files'],
  [/(^|\/)node_modules\//, 'node_modules'],
  [/\.(test|spec)\.[cm]?[jt]s$|(^|\/)__tests__\//, 'test files'],
  [/(^|\/)\.env(\.|$)/, '.env files'],
  [/(^|\/)\.npmrc$/, '.npmrc'],
  [/(^|\/)\.DS_Store$/, '.DS_Store'],
  [/(^|\/)(state\.json|audit\.log|config\.local\.json)$/, 'local state or audit data'],
  [/(^|\/)profile\//, 'browser profile data'],
  [/\.(pem|key|p12|pfx)$/i, 'key or certificate material'],
  [/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/, 'lockfiles'],
  [/\.tgz$/, 'nested tarballs'],
];
const MAX_UNPACKED = 10 * 1024 * 1024;
const MAX_FILES = 500;

const problems = [];
for (const f of REQUIRED) if (!files.includes(f)) problems.push(`missing required file: ${f}`);
for (const p of REQUIRED_PREFIXES) if (!files.some((f) => f.startsWith(p))) problems.push(`missing required content: ${p}*`);
for (const f of files) {
  const rule = FORBIDDEN.find(([re]) => re.test(f));
  if (rule) problems.push(`forbidden content (${rule[1]}): ${f}`);
}

const binPath = Object.values(pkg.bin ?? {})[0];
if (!binPath || !files.includes(binPath)) {
  problems.push(`bin entry ${binPath ?? '(none)'} is not in the tarball`);
} else if (!readFileSync(join(root, binPath), 'utf8').startsWith('#!/usr/bin/env node')) {
  problems.push(`${binPath} lacks a node shebang`);
}

if (files.length > MAX_FILES) problems.push(`too many files in tarball: ${files.length}`);
if (info.unpackedSize > MAX_UNPACKED) problems.push(`tarball too large: ${(info.unpackedSize / 1024 / 1024).toFixed(1)} MiB unpacked`);

if (problems.length) {
  console.error(`verify-pack FAILED:\n- ${problems.join('\n- ')}`);
  process.exitCode = 1;
} else {
  console.log(`verify-pack ok: ${files.length} files, ${(info.unpackedSize / 1024).toFixed(0)} KiB unpacked, bin ${binPath}`);
}
