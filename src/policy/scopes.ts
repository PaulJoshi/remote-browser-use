export const SCOPES = ['browser:read', 'browser:navigate', 'browser:interact', 'browser:manage'] as const;
export type Scope = (typeof SCOPES)[number];

export const TOOL_SCOPES = {
  requestTabAccess: 'browser:read',
  listTabs: 'browser:read',
  selectTab: 'browser:read',
  readPage: 'browser:read',
  screenshotPage: 'browser:read',
  navigatePage: 'browser:navigate',
  clickElement: 'browser:interact',
  hoverElement: 'browser:interact',
  dragElement: 'browser:interact',
  typeInPage: 'browser:interact',
  handleDialog: 'browser:interact',
  openBrowserPage: 'browser:manage',
  closeTab: 'browser:manage',
} as const satisfies Record<string, Scope>;

export type ToolName = keyof typeof TOOL_SCOPES;
export const TOOL_NAMES = Object.keys(TOOL_SCOPES) as ToolName[];

export const PRESETS = {
  readOnly: ['requestTabAccess', 'listTabs', 'selectTab', 'readPage', 'screenshotPage'],
  interactive: [
    'requestTabAccess',
    'listTabs',
    'selectTab',
    'readPage',
    'screenshotPage',
    'navigatePage',
    'clickElement',
    'hoverElement',
    'dragElement',
    'typeInPage',
    'handleDialog',
  ],
  interactiveWithTabs: TOOL_NAMES,
} as const satisfies Record<string, readonly ToolName[]>;

export type PresetName = keyof typeof PRESETS | 'none';

export function isScope(value: string): value is Scope {
  return (SCOPES as readonly string[]).includes(value);
}

export function isToolName(value: string): value is ToolName {
  return Object.hasOwn(TOOL_SCOPES, value);
}

/** Tools a client may use given its scopes and the global ceiling. */
export function toolsAllowedByScopes(scopes: readonly string[], ceiling: readonly ToolName[]): ToolName[] {
  return ceiling.filter((tool) => scopes.includes(TOOL_SCOPES[tool]));
}
