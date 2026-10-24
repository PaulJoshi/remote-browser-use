import { spawn } from 'node:child_process';

/** Open a URL in the user's default (everyday) browser — used only for the local control panel. */
export function openInDefaultBrowser(url: string): void {
  if (!/^http:\/\/(127\.0\.0\.1|localhost):\d+\/?(#k=[A-Za-z0-9-]+)?$/.test(url)) return;
  const [cmd, args] =
    process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '""', url]] : ['xdg-open', [url]];
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true, windowsHide: true });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    /* the URL is printed in the terminal anyway */
  }
}
