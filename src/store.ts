import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomToken } from './util/crypto.js';

export const DATA_DIR_ENV = 'REMOTE_BROWSER_USE_HOME';

export interface DataPaths {
  root: string;
  profile: string;
  state: string;
  audit: string;
}

export function resolveDataPaths(explicit?: string): DataPaths {
  const root = resolve(explicit ?? process.env[DATA_DIR_ENV] ?? join(homedir(), '.remote-browser-use'));
  const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  if (root === packageRoot || root.startsWith(packageRoot + sep)) {
    throw new Error(`Refusing to store private data inside the package directory (${packageRoot}).`);
  }
  return { root, profile: join(root, 'profile'), state: join(root, 'state.json'), audit: join(root, 'audit.log') };
}

/** Create a directory readable only by the current user (POSIX permissions; best effort on Windows). */
export function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    const mode = statSync(dir).mode & 0o777;
    if (mode !== 0o700) chmodSync(dir, 0o700);
  }
}

export function writePrivateFile(file: string, content: string): void {
  ensurePrivateDir(dirname(file));
  const tmp = `${file}.${randomToken(6)}.tmp`;
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, file);
  if (process.platform !== 'win32') chmodSync(file, 0o600);
}

export interface StoredDevice {
  id: string;
  hash: string;
  createdAt: number;
  lastSeen: number;
}

export interface StoredClient {
  clientId: string;
  kind: 'dcr' | 'cimd';
  name: string;
  redirectUris: string[];
  tokenEndpointAuthMethod: 'none' | 'client_secret_post' | 'client_secret_basic';
  secretHash?: string;
  createdAt: number;
  approved: boolean;
  scopes: string[];
  tools: string[];
  lastUsed?: number;
}

export interface StoredRefreshToken {
  hash: string;
  clientId: string;
  scopes: string[];
  familyId: string;
  expiresAt: number;
  used: boolean;
}

export interface PersistedState {
  version: 1;
  serverSecret: string;
  publicUrl?: string;
  ownerDevices: StoredDevice[];
  oauth: {
    /** Issuer the registrations and refresh tokens below belong to. */
    issuer?: string;
    clients: StoredClient[];
    refreshTokens: StoredRefreshToken[];
  };
}

function freshState(): PersistedState {
  return { version: 1, serverSecret: randomToken(32), ownerDevices: [], oauth: { clients: [], refreshTokens: [] } };
}

/** Owner-only JSON state file with atomic writes. */
export class StateStore {
  readonly state: PersistedState;

  constructor(private readonly file: string) {
    if (existsSync(file)) {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as PersistedState;
      if (parsed.version !== 1) throw new Error(`Unsupported state file version in ${file}`);
      this.state = { ...freshState(), ...parsed, oauth: { ...freshState().oauth, ...parsed.oauth } };
    } else {
      this.state = freshState();
      this.save();
    }
  }

  save(): void {
    writePrivateFile(this.file, JSON.stringify(this.state, null, 2));
  }
}
