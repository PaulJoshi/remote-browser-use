import { existsSync, readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { dirname, extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface FixtureServers {
  courseOrigin: string;
  playerOrigin: string;
  close(): Promise<void>;
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
};

/** Locate the bundled fictional course: dist/fixtures/course in the package, tests/fixtures/course in the repo. */
export function fixtureRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [join(here, '..', 'fixtures', 'course'), join(here, '..', '..', 'tests', 'fixtures', 'course')]) {
    if (existsSync(join(candidate, 'course', 'index.html'))) return candidate;
  }
  throw new Error('Bundled demo course files are missing.');
}

function listen(server: Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve((server.address() as { port: number }).port));
  });
}

/**
 * Serve the fictional "Northwind Security Basics" course on one loopback origin
 * and its LMS/SCORM-style player on a second origin (different port = different
 * origin), so the player is a genuinely cross-origin iframe.
 */
export async function startFixtureServers(opts: { coursePort?: number; playerPort?: number } = {}): Promise<FixtureServers> {
  const root = fixtureRoot();
  let courseOrigin = '';
  let playerOrigin = '';
  const make = (dir: string, extra?: (path: string) => { status: number; headers: Record<string, string>; body: string } | undefined) =>
    createServer((req, res) => {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const special = extra?.(url.pathname);
      if (special) {
        res.writeHead(special.status, { 'Cache-Control': 'no-store', ...special.headers });
        res.end(special.body);
        return;
      }
      const rel = url.pathname === '/' ? '/index.html' : url.pathname;
      const file = normalize(join(root, dir, rel));
      if (!file.startsWith(join(root, dir) + sep) || !existsSync(file)) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      const type = TYPES[extname(file)] ?? 'application/octet-stream';
      let body: string | Buffer = readFileSync(file);
      if (type.startsWith('text/')) body = body.toString('utf8').replaceAll('{{PLAYER_ORIGIN}}', playerOrigin).replaceAll('{{COURSE_ORIGIN}}', courseOrigin);
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(body);
    });
  const course = make('course', (path): { status: number; headers: Record<string, string>; body: string } | undefined => {
    if (path === '/redirect-to-player') return { status: 302, headers: { Location: `${playerOrigin}/landing.html` }, body: '' };
    if (path === '/redirect-to-private') return { status: 302, headers: { Location: 'http://10.255.255.1/' }, body: '' };
    if (path === '/files/handbook.txt') {
      return {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="northwind-handbook.txt"' },
        body: 'Northwind Security Basics (fictional) — handbook.\n',
      };
    }
    return undefined;
  });
  const player = make('player');
  const coursePort = await listen(course, opts.coursePort ?? 0);
  const playerPort = await listen(player, opts.playerPort ?? 0);
  courseOrigin = `http://127.0.0.1:${coursePort}`;
  playerOrigin = `http://127.0.0.1:${playerPort}`;
  return {
    courseOrigin,
    playerOrigin,
    close: async () => {
      await Promise.all([course, player].map((s) => new Promise<void>((r) => s.close(() => r()))));
      course.closeAllConnections();
      player.closeAllConnections();
    },
  };
}
