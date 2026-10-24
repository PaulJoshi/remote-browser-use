import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function findVersion(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: string; version?: string };
      if (pkg.name === 'remote-browser-use' && pkg.version) return pkg.version;
    } catch {
      /* keep looking */
    }
    dir = dirname(dir);
  }
  return '0.0.0';
}

export const VERSION = findVersion();
