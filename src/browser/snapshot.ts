import type { Frame } from 'playwright-core';
import { sanitizeText } from '../util/sanitize.js';
import { isSensitiveField } from './inspect.js';
import type { SnapshotRef, Tab } from './manager.js';

type AriaNode =
  | string
  | {
      role: string;
      name?: string;
      text?: string;
      ref?: string;
      url?: string;
      placeholder?: string;
      level?: number;
      checked?: boolean | 'mixed';
      disabled?: boolean;
      expanded?: boolean;
      pressed?: boolean | 'mixed';
      selected?: boolean;
      children?: AriaNode[];
    };

const VALUE_ROLES = new Set(['textbox', 'searchbox', 'combobox', 'spinbutton']);
const MAX_NODES = 4000;

export interface SnapshotOutput {
  lines: string[];
  refs: Map<string, SnapshotRef>;
  unsharedFrames: string[];
  truncated: boolean;
}

function quote(s: string, max = 200): string {
  return JSON.stringify(sanitizeText(s, max));
}

/** Link target without query/fragment; a marker shows there was a query. */
function safeLinkUrl(raw: string, base: string): string {
  try {
    const u = new URL(raw, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return u.protocol;
    return `${u.origin}${u.pathname}${u.search ? '?…' : ''}`;
  } catch {
    return '(relative)';
  }
}

/**
 * Frame-aware accessibility snapshot. Content from frames the client may not
 * see is dropped (only a placeholder with a frame id remains), and values of
 * password/OTP-like fields are redacted.
 */
export async function snapshotTab(tab: Tab, isAllowed: (frame: Frame) => boolean, onlyFrameId?: string): Promise<SnapshotOutput> {
  const roots = (await tab.page.ariaSnapshotJSON({ mode: 'ai', timeout: 15_000 })) as AriaNode[];
  const out: SnapshotOutput = { lines: [], refs: new Map(), unsharedFrames: [], truncated: false };
  const main = tab.page.mainFrame();
  let count = 0;

  const walk = async (node: AriaNode, frame: Frame, depth: number, emit: boolean): Promise<void> => {
    if (count >= MAX_NODES) {
      out.truncated = true;
      return;
    }
    const pad = '  '.repeat(depth);
    if (typeof node === 'string') {
      const text = sanitizeText(node, 300);
      if (text && emit) {
        out.lines.push(`${pad}- text: ${quote(text, 300)}`);
        count++;
      }
      return;
    }
    const ref = node.ref;
    if (node.role === 'iframe') {
      let child: Frame | null = null;
      if (ref) {
        const handle = await tab.page.getByRef(ref).elementHandle({ timeout: 2000 }).catch(() => null);
        child = (await handle?.contentFrame().catch(() => null)) ?? null;
        await handle?.dispose().catch(() => undefined);
      }
      if (ref) out.refs.set(ref, { frame, frameId: tab.frameId(frame), frameVersion: tab.frameVersion(frame), role: 'iframe', name: '' });
      if (!child) {
        if (emit) out.lines.push(`${pad}- iframe${ref ? ` [ref=${ref}]` : ''} (not loaded)`);
        return;
      }
      const childId = tab.frameId(child);
      if (!isAllowed(child)) {
        out.unsharedFrames.push(childId);
        if (emit) out.lines.push(`${pad}- iframe [frame=${childId}] (contents not shared with you; call requestTabAccess with frameId "${childId}" to ask the owner)`);
        count++;
        return;
      }
      const childEmit = onlyFrameId ? onlyFrameId === childId || emit : true;
      if (emit) out.lines.push(`${pad}- iframe [frame=${childId}]${ref ? ` [ref=${ref}]` : ''}:`);
      count++;
      for (const c of node.children ?? []) await walk(c, child, emit ? depth + 1 : 0, childEmit);
      return;
    }
    let text = node.text;
    if (text !== undefined && VALUE_ROLES.has(node.role) && ref) {
      if (await isSensitiveField(tab.page.getByRef(ref))) text = '[redacted]';
    }
    if (ref) out.refs.set(ref, { frame, frameId: tab.frameId(frame), frameVersion: tab.frameVersion(frame), role: node.role, name: sanitizeText(node.name ?? '', 120) });
    if (emit) {
      const attrs: string[] = [];
      if (node.level !== undefined) attrs.push(`[level=${node.level}]`);
      if (node.checked !== undefined) attrs.push(node.checked === 'mixed' ? '[checked=mixed]' : node.checked ? '[checked]' : '[unchecked]');
      if (node.pressed !== undefined) attrs.push(node.pressed ? '[pressed]' : '[not pressed]');
      if (node.expanded !== undefined) attrs.push(node.expanded ? '[expanded]' : '[collapsed]');
      if (node.selected) attrs.push('[selected]');
      if (node.disabled) attrs.push('[disabled]');
      if (node.placeholder) attrs.push(`[placeholder=${quote(node.placeholder, 80)}]`);
      if (node.url) attrs.push(`[url=${safeLinkUrl(node.url, frame.url())}]`);
      if (ref) attrs.push(`[ref=${ref}]`);
      const name = node.name ? ` ${quote(node.name)}` : '';
      const value = text !== undefined && text !== '' ? `: ${text === '[redacted]' ? text : quote(text, 300)}` : '';
      const hasChildren = (node.children?.length ?? 0) > 0;
      out.lines.push(`${pad}- ${node.role}${name}${attrs.length ? ` ${attrs.join(' ')}` : ''}${value}${hasChildren && !value ? ':' : ''}`);
      count++;
    }
    for (const c of node.children ?? []) await walk(c, frame, emit ? depth + 1 : depth, emit);
  };

  const emitMain = !onlyFrameId || onlyFrameId === 'main';
  for (const root of roots) await walk(root, main, 0, emitMain);
  if (out.truncated) out.lines.push(`… snapshot truncated after ${MAX_NODES} elements; use readPage with frameId or mode "text" for more`);
  return out;
}

/** Readable text of the main frame and every frame the client may see. */
export async function pageText(tab: Tab, isAllowed: (frame: Frame) => boolean, onlyFrameId?: string): Promise<string> {
  const parts: string[] = [];
  for (const frame of tab.page.frames()) {
    if (frame.isDetached()) continue;
    const id = tab.frameId(frame);
    if (onlyFrameId && onlyFrameId !== id) continue;
    if (!isAllowed(frame)) {
      parts.push(`[frame ${id}: contents not shared with you]`);
      continue;
    }
    const text = await frame
      .locator('body')
      .innerText({ timeout: 5000 })
      .catch(() => '');
    // eslint-disable-next-line no-control-regex
    const cleaned = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').replace(/\n{3,}/g, '\n\n').slice(0, 200_000);
    parts.push(id === 'main' ? cleaned : `[frame ${id}]\n${cleaned}`);
  }
  return parts.join('\n\n');
}
