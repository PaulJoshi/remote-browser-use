#!/usr/bin/env node
import { App } from '../app.js';
import { ConfigError, HELP_TEXT, loadConfigFile, parseArgs, resolveConfig } from '../config.js';
import { startFixtureServers, type FixtureServers } from '../demo/fixtureServer.js';
import { VERSION } from '../version.js';
import { ensureChromium } from './chromium.js';
import { openInDefaultBrowser } from './openUrl.js';

const [major, minor] = process.versions.node.split('.').map(Number) as [number, number];
if (major < 22 || (major === 22 && minor < 12)) {
  console.error(`remote-browser-use needs Node.js 22.12 or newer (you have ${process.versions.node}). Install a current LTS from https://nodejs.org/.`);
  process.exit(1);
}

const out = (line = ''): void => {
  process.stdout.write(`${line}\n`);
};

async function main(): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(`Error: ${error.message}`);
      process.exit(2);
    }
    throw error;
  }
  if (parsed.command === 'help') return out(HELP_TEXT);
  if (parsed.command === 'version') return out(VERSION);

  let config;
  try {
    config = resolveConfig(parsed.configPath ? loadConfigFile(parsed.configPath) : {}, parsed.cli);
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(`Error: ${error.message}`);
      process.exit(2);
    }
    throw error;
  }

  out(`remote-browser-use ${VERSION}`);
  await ensureChromium(out);

  let fixtures: FixtureServers | undefined;
  if (parsed.command === 'demo') fixtures = await startFixtureServers();

  out('Starting the dedicated browser (separate profile, not your everyday Chrome)...');
  const app = await App.start({
    config,
    localOriginExceptions: fixtures ? [fixtures.courseOrigin, fixtures.playerOrigin] : [],
    initialUrls: fixtures ? [`${fixtures.courseOrigin}/`] : [],
    log: (line) => out(line),
    onSetupCode: (code) => out(`\nThe setup code was used. New owner setup code (for another browser): ${code}`),
  });

  const identity = app.auth.identity();
  out('');
  out(`Browser profile:   ${app.paths.profile}`);
  out(`Control panel:     ${app.adminUrl}   (local only — never forward this port)`);
  out(`MCP endpoint:      ${app.mcpUrl}   (forward port ${config.port} over HTTPS)`);
  out(`Owner setup code:  ${app.setupCode}   (type it into the control panel; do not share it)`);
  out('');
  if (identity) {
    out(`Public URL:        ${identity.baseUrl}${config.publicUrl ? '' : '   (saved from a previous run; change it in the panel if your tunnel URL changed)'}`);
    out(`Chat connector URL: ${identity.mcpUrl}`);
  } else {
    out(`Next: forward port ${config.port} over HTTPS (VS Code Ports view → set visibility to Public),`);
    out('      then paste the https URL into the control panel and add its /mcp URL to your chat app.');
  }
  if (fixtures) {
    out('');
    out(`Demo course:       ${fixtures.courseOrigin}/   (fictional; its player frame is on ${fixtures.playerOrigin})`);
    out('      Share the course tab with your chat app in the control panel, then ask it to complete the course.');
  }
  out('');
  out('Press Ctrl+C to stop. Stopping ends all remote access; your browser profile is kept.');
  if (config.openPanel) openInDefaultBrowser(app.adminUrl);

  let stopping = false;
  const stop = async (reason: string) => {
    if (stopping) {
      out('Forcing exit.');
      process.exit(1);
    }
    stopping = true;
    out(`\n${reason} Shutting down...`);
    await app.stop();
    await fixtures?.close();
    out('Stopped. Remote access has ended.');
    process.exit(0);
  };
  process.on('SIGINT', () => void stop('Received Ctrl+C.'));
  process.on('SIGTERM', () => void stop('Received SIGTERM.'));
  process.on('SIGHUP', () => void stop('The terminal closed.'));
  app.browser.on('closed', () => void stop('The browser window was closed.'));
}

main().catch((error: unknown) => {
  console.error(`Error: ${(error as Error).message ?? String(error)}`);
  process.exit(1);
});
