import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { authorizeClient, call, mcpClient, startHarness, type Harness } from './harness.js';

describe('smoke: OAuth + MCP + shared tab read', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await startHarness();
    await h.app.browser.openTab(`${h.fixtures.courseOrigin}/`);
  });
  afterAll(async () => h?.stop());

  for (const era of ['modern', 'legacy'] as const) {
    it(`connects over the ${era} protocol era and reads only a shared tab`, async () => {
      const oauth = await authorizeClient(h, { name: `Smoke ${era}` });
      const client = await mcpClient(h, oauth.accessToken, era);
      expect(client.getNegotiatedProtocolVersion()).toBe(era === 'modern' ? '2026-07-28' : '2025-11-25');
      const tools = await client.listTools();
      expect(tools.tools.map((t) => t.name).sort()).toContain('readPage');
      const empty = await call(client, 'listTabs');
      expect(empty.text).toMatch(/No tabs are shared/);
      const tabId = await h.admin.tabIdFor(h.fixtures.courseOrigin);
      await h.admin.ok('/api/grant', { action: 'share', clientId: oauth.clientId, tabId });
      const list = await call(client, 'listTabs');
      expect(list.text).toContain(tabId);
      expect(list.text).toContain('Northwind Security Basics');
      const read = await call(client, 'readPage', {});
      expect(read.isError).toBe(false);
      expect(read.text).toContain('Security awareness course 2026');
      expect(read.text).toMatch(/\[ref=e\d+\]/);
      await client.close();
    });
  }
});
