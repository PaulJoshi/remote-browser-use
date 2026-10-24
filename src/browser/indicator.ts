import type { Page } from 'playwright-core';

const SCRIPT = (args: { show: boolean; label: string; active: boolean }) => {
  const ID = '__remote_browser_use_indicator__';
  document.getElementById(ID)?.remove();
  if (!args.show) return true;
  const host = document.createElement('rbu-indicator');
  host.id = ID;
  host.setAttribute('aria-hidden', 'true');
  (host as HTMLElement & { inert: boolean }).inert = true;
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `:host{all:initial}
.f{position:fixed;inset:0;pointer-events:none;z-index:2147483647;box-shadow:inset 0 0 0 3px #7c3aed}
.p{position:fixed;right:10px;bottom:10px;pointer-events:none;z-index:2147483647;font:600 12px/1.2 system-ui,sans-serif;
color:#fff;background:#7c3aed;padding:6px 10px;border-radius:999px;box-shadow:0 2px 8px rgba(0,0,0,.25);opacity:.92}
.a{background:#c2410c}`;
  const frame = document.createElement('div');
  frame.className = 'f';
  const pill = document.createElement('div');
  pill.className = args.active ? 'p a' : 'p';
  pill.textContent = args.active ? `AI agent acting (${args.label})` : `Shared with AI: ${args.label}`;
  root.append(style, frame, pill);
  document.documentElement.appendChild(host);
  return true;
};

/** Inject or remove the visible "shared with AI" indicator. Returns false where injection is impossible. */
export async function setIndicator(page: Page, show: boolean, label = '', active = false): Promise<boolean> {
  if (page.isClosed()) return false;
  try {
    return await page.mainFrame().evaluate(SCRIPT, { show, label: label.slice(0, 60), active });
  } catch {
    return false;
  }
}
