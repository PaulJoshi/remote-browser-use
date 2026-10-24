import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { normalizePublicUrl } from './auth/publicUrl.js';
import { isToolName, TOOL_NAMES, type ToolName } from './policy/scopes.js';

export type ApprovalMode = 'sensitive' | 'all';

export interface ResolvedConfig {
  port: number;
  adminPort: number;
  publicUrl?: string;
  toolCeiling: ToolName[];
  allowDomains: string[];
  denyDomains: string[];
  approve: ApprovalMode;
  approvalTimeoutSeconds: number;
  openPanel: boolean;
}

export type Command = 'start' | 'demo' | 'help' | 'version';

export class ConfigError extends Error {}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function parseDomain(raw: string): string {
  const value = raw.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!DOMAIN_RE.test(value)) throw new ConfigError(`Invalid domain "${raw}". Use bare hostnames like example.com.`);
  return value;
}

function parseList(value: string | string[]): string[] {
  const items = Array.isArray(value) ? value : value.split(',');
  return items.map((s) => s.trim()).filter(Boolean);
}

function parseTools(value: string | string[]): ToolName[] {
  const items = parseList(value);
  if (items.length === 1 && items[0] === 'all') return [...TOOL_NAMES];
  if (items.length === 1 && items[0] === 'none') return [];
  for (const item of items) {
    if (!isToolName(item)) throw new ConfigError(`Unknown tool "${item}". Valid tools: ${TOOL_NAMES.join(', ')}, or "all".`);
  }
  return [...new Set(items as ToolName[])];
}

function parsePort(value: string | number, flag: string): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || n < 1024 || n > 65535) throw new ConfigError(`${flag} must be an integer between 1024 and 65535.`);
  return n;
}

const fileSchema = z
  .object({
    port: z.number().int().optional(),
    adminPort: z.number().int().optional(),
    publicUrl: z.string().optional(),
    tools: z.union([z.string(), z.array(z.string())]).optional(),
    allowDomains: z.union([z.string(), z.array(z.string())]).optional(),
    denyDomains: z.union([z.string(), z.array(z.string())]).optional(),
    approve: z.enum(['sensitive', 'all']).optional(),
    approvalTimeoutSeconds: z.number().int().min(10).max(300).optional(),
    openPanel: z.boolean().optional(),
  })
  .strict();

export type FileConfig = z.infer<typeof fileSchema>;

export function loadConfigFile(path: string): FileConfig {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    throw new ConfigError(`Cannot read config file ${path}: ${(error as Error).message}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new ConfigError(`Config file ${path} is not valid JSON.`);
  }
  const parsed = fileSchema.safeParse(json);
  if (!parsed.success) {
    throw new ConfigError(`Invalid config file ${path}: ${parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')}`);
  }
  return parsed.data;
}

export interface ParsedArgs {
  command: Command;
  cli: FileConfig;
  configPath?: string;
}

const VALUE_FLAGS: Record<string, keyof FileConfig | 'config'> = {
  '--port': 'port',
  '--admin-port': 'adminPort',
  '--public-url': 'publicUrl',
  '--tools': 'tools',
  '--allow-domains': 'allowDomains',
  '--deny-domains': 'denyDomains',
  '--approve': 'approve',
  '--approval-timeout': 'approvalTimeoutSeconds',
  '--config': 'config',
};

export function parseArgs(argv: string[]): ParsedArgs {
  const cli: Record<string, unknown> = {};
  let command: Command = 'start';
  let configPath: string | undefined;
  const args = [...argv];
  if (args[0] === 'demo') {
    command = 'demo';
    args.shift();
  }
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--help' || arg === '-h') return { command: 'help', cli: {} };
    if (arg === '--version' || arg === '-v') return { command: 'version', cli: {} };
    if (arg === '--no-open') {
      cli.openPanel = false;
      continue;
    }
    const [flag, inline] = arg.includes('=') ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)] : [arg, undefined];
    const key = VALUE_FLAGS[flag];
    if (!key) throw new ConfigError(`Unknown option "${arg}". Run remote-browser-use --help.`);
    const value = inline ?? args[++i];
    if (value === undefined || (inline === undefined && value.startsWith('--'))) throw new ConfigError(`${flag} requires a value.`);
    if (key === 'config') configPath = value;
    else if (key === 'port' || key === 'adminPort') cli[key] = parsePort(value, flag);
    else if (key === 'approvalTimeoutSeconds') {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 10 || n > 300) throw new ConfigError(`${flag} must be between 10 and 300 seconds.`);
      cli[key] = n;
    } else if (key === 'approve') {
      if (value !== 'sensitive' && value !== 'all') throw new ConfigError('--approve must be "sensitive" or "all".');
      cli[key] = value;
    } else cli[key] = value;
  }
  return { command, cli: cli as FileConfig, configPath };
}

export function resolveConfig(file: FileConfig, cli: FileConfig): ResolvedConfig {
  const merged: FileConfig = { ...file, ...cli };
  const port = parsePort(merged.port ?? 8931, 'port');
  const adminPort = parsePort(merged.adminPort ?? 8932, 'adminPort');
  if (port === adminPort) throw new ConfigError('The MCP port and admin port must be different.');
  let publicUrl: string | undefined;
  if (merged.publicUrl) {
    try {
      publicUrl = normalizePublicUrl(merged.publicUrl, port);
    } catch (error) {
      throw new ConfigError((error as Error).message);
    }
  }
  return {
    port,
    adminPort,
    publicUrl,
    toolCeiling: merged.tools === undefined ? [...TOOL_NAMES] : parseTools(merged.tools),
    allowDomains: merged.allowDomains ? parseList(merged.allowDomains).map(parseDomain) : [],
    denyDomains: merged.denyDomains ? parseList(merged.denyDomains).map(parseDomain) : [],
    approve: merged.approve ?? 'sensitive',
    approvalTimeoutSeconds: merged.approvalTimeoutSeconds ?? 60,
    openPanel: merged.openPanel ?? true,
  };
}

export const HELP_TEXT = `remote-browser-use — share selected tabs of a separate Chromium browser with an MCP chat app

Usage:
  npx remote-browser-use [options]        start the browser, MCP server and local control panel
  npx remote-browser-use demo [options]   same, plus a bundled fictional training course to try

Options:
  --port <n>                 MCP/OAuth port to forward over HTTPS (default 8931)
  --admin-port <n>           local-only control panel port, never forward it (default 8932)
  --public-url <https-url>   the HTTPS base URL your tunnel forwards to --port
                             (can also be entered later in the control panel)
  --tools <list|all>         maximum tools the panel may enable (default all; none enabled until you choose)
  --allow-domains <list>     only allow granting/navigating these domains (and subdomains)
  --deny-domains <list>      never allow these domains (deny wins)
  --approve sensitive|all    which agent actions need your approval (default sensitive)
  --approval-timeout <sec>   seconds before an unanswered approval is denied (default 60)
  --config <path>            JSON file with the same settings (flags override it)
  --no-open                  do not open the control panel in your default browser
  -h, --help                 show this help
  -v, --version              show the version

Steps after starting:
  1. Sign in to sites in the dedicated browser window that opens (not your normal Chrome).
  2. Forward ONLY the MCP port over HTTPS (VS Code Ports view: set visibility to Public).
  3. Paste the forwarded https URL into the control panel; add <url>/mcp to your chat app.
  4. Approve the chat app and share specific tabs in the control panel.

Data (browser profile, owner keys, audit metadata) lives in ~/.remote-browser-use
(override with REMOTE_BROWSER_USE_HOME).`;
