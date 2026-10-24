'use strict';
(() => {
  let csrf = '';
  let state = null;
  const drafts = {};
  const rendered = {};
  const $ = (id) => document.getElementById(id);

  // Build DOM nodes without ever interpreting strings as HTML (tab titles etc. are untrusted).
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
      else if (k === 'checked' || k === 'disabled' || k === 'hidden' || k === 'value' || k === 'selected') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  async function api(path, body) {
    const res = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf } : {},
      body: body ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  function flash(message, bad) {
    const el = $('flash');
    el.textContent = message;
    el.className = bad ? 'flash bad' : 'flash';
    el.hidden = false;
    clearTimeout(flash.t);
    flash.t = setTimeout(() => (el.hidden = true), 6000);
  }

  async function act(path, body, ok) {
    try {
      await api(path, body);
      if (ok) flash(ok);
      await refresh(true);
    } catch (e) {
      flash(e.message, true);
    }
  }

  function copyButton(text) {
    return h('button', { onclick: () => navigator.clipboard.writeText(text).then(() => flash('Copied.')) }, 'Copy');
  }

  function clientName(id) {
    const c = state.clients.find((x) => x.clientId === id);
    return c ? c.name : id;
  }

  function secondsLeft(expiresAt) {
    return Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  }

  // ------------------------------------------------------------------ sections

  function renderSetup() {
    const s = state;
    const urlInput = h('input', { type: 'url', id: 'public-url', placeholder: 'https://your-tunnel-8931.example.devtunnels.ms', value: drafts.publicUrl ?? '' });
    urlInput.addEventListener('input', () => (drafts.publicUrl = urlInput.value));
    const save = h('button', {
      class: 'primary',
      onclick: () => {
        const url = urlInput.value.trim();
        if (s.publicUrl && url !== s.publicUrl && !confirm('Changing the public URL disconnects every chat app. They will need to reconnect and be approved again. Continue?')) return;
        drafts.publicUrl = undefined;
        act('/api/public-url', { url }, 'Public URL saved.');
      },
    }, s.publicUrl ? 'Change' : 'Save');
    return [
      h('h2', {}, 'Connect a chat app'),
      h('ol', { class: 'steps' },
        h('li', {}, 'Sign in to the sites you need in the ', h('strong', {}, 'remote-browser-use browser window'), ' (not your normal Chrome).'),
        h('li', {}, 'Forward ', h('strong', {}, `port ${s.mcpPort} only`), ' over HTTPS. In VS Code: Ports view → Forward a Port → ', h('code', {}, String(s.mcpPort)), ' → right-click → Port Visibility → ', h('strong', {}, 'Public'),
          '. Public makes it reachable; OAuth still protects it. ', h('strong', { class: 'error' }, `Never forward port ${s.adminPort}`), ' (this panel).'),
        h('li', {}, 'Paste the forwarded https base URL here:',
          h('div', { class: 'row' }, urlInput, save),
          s.publicUrl ? h('div', { class: 'muted' }, 'Current: ', h('code', {}, s.publicUrl)) : h('div', { class: 'muted' }, 'Not set yet — chat apps cannot connect until it is.')),
        h('li', {}, 'Add this connector URL in your chat app (ChatGPT: add a custom MCP server; Claude: add a custom connector), then approve it below:',
          s.connectorUrl ? h('div', { class: 'row' }, h('code', {}, s.connectorUrl), copyButton(s.connectorUrl)) : h('div', { class: 'muted' }, '(set the public URL first)')),
        h('li', {}, 'Share specific tabs with the approved app (Tabs section).'),
      ),
      h('p', { class: 'muted' },
        `Approvals: ${s.approvalMode} (unanswered requests are denied after ${s.approvalTimeoutSeconds}s). `,
        `Tool ceiling: ${s.toolCeiling.length} of 13 tools. `,
        s.allowDomains.length ? `Allowed domains: ${s.allowDomains.join(', ')}. ` : '',
        s.denyDomains.length ? `Denied domains: ${s.denyDomains.join(', ')}. ` : '',
        s.localExceptions.length ? `Local demo origins allowed: ${s.localExceptions.join(', ')}.` : ''),
    ];
  }

  function presetTools(preset, allowed) {
    if (preset === 'none') return [];
    return (state.presets[preset] || []).filter((t) => allowed.includes(t));
  }

  function authorizationCard(p) {
    const d = (drafts[p.id] ??= { scopes: [...p.requestedScopes], preset: 'readOnly' });
    const allowedFor = () => state.toolCeiling.filter((t) => d.scopes.includes(state.toolScopes[t]));
    return h('div', { class: 'card attention' },
      h('h3', {}, 'Connection request: ', p.clientName),
      h('div', {}, p.verifiedHost ? h('span', { class: 'tag shared' }, `verified domain: ${p.verifiedHost}`) : h('span', { class: 'tag warn' }, 'self-declared name (not verified)'),
        p.previouslyApproved ? h('span', { class: 'tag' }, 'previously approved') : null),
      h('div', { class: 'row' }, 'Match code (must equal the code on the chat app\'s login page):', h('span', { class: 'code-big' }, p.matchCode)),
      h('div', { class: 'muted' }, 'Redirects to: ', h('code', {}, p.redirectUri)),
      h('div', { class: 'row' }, 'Scopes:', ...p.requestedScopes.map((s) =>
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d.scopes.includes(s), onchange: (e) => {
          d.scopes = e.target.checked ? [...d.scopes, s] : d.scopes.filter((x) => x !== s);
        } }), s))),
      h('div', { class: 'row' }, 'Enable tools:', ...[['readOnly', 'Read-only'], ['interactive', 'Interactive'], ['interactiveWithTabs', 'Interactive + open/close tabs'], ['none', 'None yet']].map(([k, label]) =>
        h('label', { class: 'check' }, h('input', { type: 'radio', name: `preset-${p.id}`, checked: d.preset === k, onchange: () => (d.preset = k) }), label))),
      h('div', { class: 'row' },
        h('button', { class: 'primary', onclick: () => act('/api/authorization', { id: p.id, decision: 'approve', scopes: d.scopes, tools: presetTools(d.preset, allowedFor()) }, `Approved ${p.clientName}.`) }, 'Approve'),
        h('button', { onclick: () => act('/api/authorization', { id: p.id, decision: 'deny' }, 'Denied.') }, 'Deny'),
        h('span', { class: 'muted' }, `expires in ${secondsLeft(p.expiresAt)}s`)),
    );
  }

  function tabAccessCard(a) {
    const shareable = state.tabs.filter((t) => t.shareable);
    const d = (drafts[a.id] ??= { tabId: a.details?.requestedTabId && shareable.some((t) => t.tabId === a.details.requestedTabId) ? a.details.requestedTabId : shareable[0]?.tabId, frames: [] });
    const tab = state.tabs.find((t) => t.tabId === d.tabId);
    const frameOrigins = tab ? [...new Set(tab.frames.map((f) => f.origin).filter((o) => o !== tab.origin && o !== 'null'))] : [];
    return h('div', { class: 'card attention' },
      h('h3', {}, `${a.clientName} asks you to share a tab`),
      a.details?.reason ? h('div', {}, 'Reason given by the agent (untrusted): ', h('em', {}, a.details.reason)) : null,
      shareable.length === 0
        ? h('p', { class: 'error' }, 'No tab is on a shareable site. Open the site in the remote-browser-use window first.')
        : h('div', { class: 'row' }, 'Tab:', h('select', { onchange: (e) => { d.tabId = e.target.value; d.frames = []; render(true); } },
            ...shareable.map((t) => h('option', { value: t.tabId, selected: t.tabId === d.tabId }, `${t.tabId} — ${t.title || '(untitled)'} — ${t.url}`)))),
      tab ? h('div', { class: 'muted' }, 'Shares site: ', h('code', {}, tab.origin)) : null,
      frameOrigins.length ? h('div', { class: 'row' }, 'Also share embedded frames from:', ...frameOrigins.map((o) =>
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: d.frames.includes(o), onchange: (e) => {
          d.frames = e.target.checked ? [...d.frames, o] : d.frames.filter((x) => x !== o);
        } }), o))) : null,
      h('div', { class: 'row' },
        h('button', { class: 'primary', disabled: !tab, onclick: () => act('/api/approval', { id: a.id, decision: 'approve', tabId: d.tabId, origins: [tab.origin], frameOrigins: d.frames }, 'Tab shared.') }, 'Share this tab'),
        h('button', { onclick: () => act('/api/approval', { id: a.id, decision: 'deny' }, 'Denied.') }, 'Deny'),
        h('span', { class: 'muted' }, `auto-deny in ${secondsLeft(a.expiresAt)}s`)),
    );
  }

  function approvalCard(a) {
    if (a.kind === 'tab_access') return tabAccessCard(a);
    const buttons = a.kind === 'open_tab'
      ? [
          h('button', { class: 'primary', onclick: () => act('/api/approval', { id: a.id, decision: 'approve', share: true }, 'Opened and shared.') }, 'Open & share with agent'),
          h('button', { onclick: () => act('/api/approval', { id: a.id, decision: 'approve', share: false }, 'Opened (not shared).') }, 'Open only'),
        ]
      : [h('button', { class: 'primary', onclick: () => act('/api/approval', { id: a.id, decision: 'approve' }, 'Approved.') }, 'Approve')];
    return h('div', { class: 'card attention' },
      h('h3', {}, `${a.clientName}: approval needed (${a.kind.replace(/_/g, ' ')})`),
      h('div', {}, a.summary),
      h('div', { class: 'row' }, ...buttons,
        h('button', { onclick: () => act('/api/approval', { id: a.id, decision: 'deny' }, 'Denied.') }, 'Deny'),
        h('span', { class: 'muted' }, `auto-deny in ${secondsLeft(a.expiresAt)}s`)),
    );
  }

  function renderPending() {
    const items = [...state.pendingAuthorizations.map(authorizationCard), ...state.approvals.map(approvalCard)];
    if (!items.length) return [];
    return [h('h2', {}, `Waiting for you (${items.length})`), ...items];
  }

  function renderTabs() {
    const approved = state.clients.filter((c) => c.approved);
    const openInput = h('input', { type: 'url', placeholder: 'https://example.com', value: drafts.openUrl ?? '' });
    openInput.addEventListener('input', () => (drafts.openUrl = openInput.value));
    return [
      h('h2', {}, 'Tabs in the remote-browser-use browser'),
      h('p', { class: 'muted' }, state.settings?.shareEntireBrowser ? 'Every tab in this browser is shared with all connected chat apps. Enable explicit sharing in Advanced security settings to restrict this.' : 'Only tabs you share are visible to an agent, and only on the sites listed. New tabs and popups are never shared automatically.'),
      ...state.tabs.map((t) => {
        const tabGrants = state.grants.filter((g) => g.tabId === t.tabId);
        const frameOrigins = [...new Set(t.frames.map((f) => f.origin).filter((o) => o !== t.origin && o !== 'null'))];
        return h('div', { class: 'card' },
          h('div', {}, h('strong', {}, t.title || '(untitled)'), ' ', h('span', { class: 'muted' }, t.tabId)),
          h('div', { class: 'muted' }, h('code', {}, t.url)),
          h('div', {},
            ...tabGrants.map((g) => h('span', { class: 'tag shared' }, `shared with ${clientName(g.clientId)}`)),
            t.agentActive ? h('span', { class: 'tag warn' }, 'agent acting now') : null,
            tabGrants.length && t.indicator === 'unavailable' ? h('span', { class: 'tag warn' }, 'in-page indicator unavailable on this page') : null,
            t.openerTabId ? h('span', { class: 'tag' }, `opened from ${t.openerTabId}`) : null,
            !t.shareable ? h('span', { class: 'tag' }, 'not shareable (local/internal page or domain rule)') : null),
          ...tabGrants.map((g) => h('div', { class: 'row' },
            `${clientName(g.clientId)} may use: `, ...g.origins.map((o) => h('code', {}, o)),
            ...frameOrigins.map((o) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: g.frameOrigins.includes(o), onchange: (e) => {
              const next = e.target.checked ? [...g.frameOrigins, o] : g.frameOrigins.filter((x) => x !== o);
              act('/api/grant', { action: 'set', clientId: g.clientId, tabId: t.tabId, origins: g.origins, frameOrigins: next }, 'Frame access updated.');
            } }), `frame ${o}`)),
            h('button', { class: 'danger', onclick: () => act('/api/grant', { action: 'revoke', clientId: g.clientId, tabId: t.tabId }, 'Stopped sharing.') }, 'Stop sharing'))),
          t.shareable ? h('div', { class: 'row' }, ...approved.filter((c) => !tabGrants.some((g) => g.clientId === c.clientId)).map((c) =>
            h('button', { onclick: () => act('/api/grant', { action: 'share', clientId: c.clientId, tabId: t.tabId }, `Shared with ${c.name}.`) }, `Share with ${c.name}`))) : null,
        );
      }),
      h('div', { class: 'row' }, openInput, h('button', { onclick: () => { const url = openInput.value.trim(); drafts.openUrl = ''; act('/api/tab', { action: 'open', url }, 'Opened.'); } }, 'Open in remote-browser-use browser')),
    ];
  }

  function renderClients() {
    if (!state.clients.length) return [h('h2', {}, 'Chat apps'), h('p', { class: 'muted' }, 'No chat app has connected yet.')];
    return [
      h('h2', {}, 'Chat apps'),
      ...state.clients.map((c) => h('div', { class: 'card' },
        h('div', {}, h('strong', {}, c.name), ' ', c.verifiedHost ? h('span', { class: 'tag shared' }, c.verifiedHost) : h('span', { class: 'tag warn' }, 'unverified name'),
          c.approved ? h('span', { class: 'tag' }, 'approved') : h('span', { class: 'tag' }, 'not approved'), h('span', { class: 'muted' }, ` ${c.activeTokens} active token(s)`)),
        h('div', { class: 'muted' }, 'Scopes: ', c.scopes.length ? c.scopes.join(', ') : '(none)'),
        c.approved ? h('div', { class: 'row' }, 'Tools:', ...c.allowedTools.map((t) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.tools.includes(t), onchange: (e) => {
          const next = e.target.checked ? [...c.tools, t] : c.tools.filter((x) => x !== t);
          act('/api/client', { clientId: c.clientId, action: 'tools', tools: next }, 'Tools updated.');
        } }), t))) : null,
        h('div', { class: 'row' },
          c.approved ? h('button', { onclick: () => act('/api/client', { clientId: c.clientId, action: 'revoke' }, 'Client revoked.') }, 'Revoke access') : null,
          h('button', { onclick: () => confirm(`Remove ${c.name}?`) && act('/api/client', { clientId: c.clientId, action: 'remove' }, 'Client removed.') }, 'Remove')),
      )),
    ];
  }

  function renderAdvanced() {
    const s = state.settings ?? {};
    const strict = (key, label) => h('label', { class: 'check' },
      h('input', { type: 'checkbox', checked: !s[key], onchange: (e) => act('/api/settings', { [key]: !e.target.checked }, 'Settings updated.') }), label);
    const approvalSel = h('select', { onchange: (e) => act('/api/settings', { actionApprovals: e.target.value }, 'Settings updated.') },
      ...[['never', 'Never ask me'], ['sensitive', 'Sensitive actions only'], ['all', 'Every action']].map(([v, l]) => h('option', { value: v, selected: s.actionApprovals === v }, l)));
    return [
      h('h2', {}, 'Advanced security settings'),
      h('p', { class: 'muted' }, 'By default everything in this dedicated browser is available to connected chat apps. Enable stricter controls below — recommended once you sign in to real accounts here.'),
      h('div', { class: 'card' },
        h('div', { class: 'row' }, strict('autoApproveClients', 'Require my approval before a chat app connects')),
        h('div', { class: 'row' }, strict('shareEntireBrowser', 'Require me to share tabs and sites explicitly')),
        h('div', { class: 'row' }, h('label', {}, 'Ask me to approve agent actions: ', approvalSel))),
    ];
  }

  function renderActivity() {
    return [
      h('h2', {}, 'Recent activity (metadata only)'),
      h('table', {}, h('tr', {}, ...['time', 'event', 'tool', 'client', 'tab', 'decision', 'ms'].map((c) => h('th', {}, c))),
        ...state.audit.map((e) => h('tr', {}, h('td', {}, new Date(e.ts).toLocaleTimeString()), h('td', {}, e.event), h('td', {}, e.tool || ''), h('td', {}, e.client ? clientName(e.client) : ''), h('td', {}, e.tab || ''), h('td', {}, [e.decision, e.reason].filter(Boolean).join(' / ')), h('td', {}, e.ms ?? '')))),
    ];
  }

  const sections = { setup: renderSetup, pending: renderPending, tabs: renderTabs, clients: renderClients, advanced: renderAdvanced, activity: renderActivity };
  const keys = {
    setup: (s) => [s.publicUrl, s.connectorUrl],
    pending: (s) => [s.pendingAuthorizations, s.approvals, s.tabs.map((t) => [t.tabId, t.title, t.url, t.shareable, t.frames]), Math.floor(Date.now() / 5000)],
    tabs: (s) => [s.tabs, s.grants, s.clients.map((c) => [c.clientId, c.approved, c.name])],
    clients: (s) => s.clients,
    advanced: (s) => s.settings,
    activity: (s) => s.audit,
  };

  function render(force) {
    for (const [id, fn] of Object.entries(sections)) {
      const el = $(id);
      const key = JSON.stringify(keys[id](state));
      if (!force && rendered[id] === key) continue;
      if (!force && el.contains(document.activeElement) && document.activeElement.tagName !== 'BUTTON') continue;
      rendered[id] = key;
      el.replaceChildren(...fn());
    }
  }

  async function refresh(force) {
    try {
      state = await api('/api/state');
      $('version').textContent = `v${state.version}`;
      render(force);
    } catch (e) {
      if (/login required/i.test(e.message)) return start();
    }
  }

  async function start() {
    // The CLI opens the panel with the one-time setup code in the URL fragment
    // (#k=...); fragments are never sent to the server. Strip it immediately.
    const linkCode = location.hash.startsWith('#k=') ? location.hash.slice(3) : '';
    if (linkCode) history.replaceState(null, '', location.pathname);
    let session = await api('/api/session').catch(() => ({ authenticated: false }));
    if (!session.authenticated && linkCode) {
      try {
        await api('/api/login', { code: linkCode });
        session = await api('/api/session').catch(() => ({ authenticated: false }));
      } catch (err) {
        $('login-error').textContent = `Automatic sign-in did not work (${err.message}). Type the code printed in the terminal instead.`;
      }
    }
    if (!session.authenticated) {
      $('login').hidden = false;
      $('main').hidden = true;
      $('kill').hidden = true;
      return;
    }
    csrf = session.csrf;
    $('login').hidden = true;
    $('main').hidden = false;
    $('kill').hidden = false;
    await refresh(true);
    clearInterval(start.timer);
    start.timer = setInterval(() => refresh(false), 1000);
  }

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/login', { code: $('code').value });
      $('login-error').textContent = '';
      await start();
    } catch (err) {
      $('login-error').textContent = err.message;
    }
  });
  $('kill').addEventListener('click', () => {
    if (confirm('Stop all agent access now? This revokes every token, tab share and pending request. Chat apps must be approved again.')) act('/api/kill', {}, 'All agent access stopped.');
  });
  start();
})();
