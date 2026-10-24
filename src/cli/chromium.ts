import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { chromium } from 'playwright-core';

const require = createRequire(import.meta.url);

export function chromiumExecutable(): string {
  return chromium.executablePath();
}

export function chromiumInstalled(): boolean {
  try {
    return existsSync(chromiumExecutable());
  } catch {
    return false;
  }
}

/**
 * Download the Chromium build matching the bundled playwright-core, if missing.
 * Uses Playwright's own installer (progress bars on a TTY); never touches the
 * user's installed Chrome. Respects PLAYWRIGHT_BROWSERS_PATH / HTTPS_PROXY.
 */
export async function ensureChromium(log: (line: string) => void): Promise<void> {
  if (chromiumInstalled()) return;
  log('First run: downloading the Chromium build this version uses (about 190 MB, stored in the shared Playwright browser cache).');
  const cli = join(dirname(require.resolve('playwright-core/package.json')), 'cli.js');
  const code = await new Promise<number>((resolve) => {
    const child = spawn(process.execPath, [cli, 'install', '--no-shell', '--no-remove', 'chromium'], { stdio: ['ignore', 'inherit', 'inherit'] });
    child.on('error', () => resolve(1));
    child.on('exit', (c) => resolve(c ?? 1));
  });
  if (code !== 0 || !chromiumInstalled()) {
    throw new Error(
      [
        'Could not download Chromium.',
        '- Check your internet connection (and HTTPS_PROXY if you are behind a proxy).',
        '- Make sure there is about 600 MB of free disk space.',
        '- To use a mirror, set PLAYWRIGHT_DOWNLOAD_HOST. To store browsers elsewhere, set PLAYWRIGHT_BROWSERS_PATH.',
        '- On Linux you may also need system libraries: npx playwright-core install-deps chromium',
      ].join('\n'),
    );
  }
  log('Chromium downloaded.');
}
