import type { ElementHandle, Locator } from 'playwright-core';

export interface ElementInfo {
  tag: string;
  type: string;
  role: string;
  label: string;
  inForm: boolean;
  isSubmit: boolean;
  href?: string;
  linkTarget?: string;
  download: boolean;
  fileInput: boolean;
  sensitive: boolean;
  editable: boolean;
  multiline: boolean;
}

/**
 * Runs inside the page. The page is untrusted and can tamper with its own DOM,
 * so this is a best-effort classifier; callers must fail towards approval.
 */
const describe = (el: Element): ElementInfo => {
  const attr = (e: Element, n: string) => (e.getAttribute(n) || '').toLowerCase();
  const tag = el.tagName.toLowerCase();
  const type = attr(el, 'type');
  const control = el.closest('button, input, a[href], [role="button"], [role="link"]') || el;
  const ctag = control.tagName.toLowerCase();
  const ctype = attr(control, 'type');
  const form = (control as HTMLButtonElement).form || control.closest('form');
  const link = el.closest('a[href]') as HTMLAnchorElement | null;
  const input = el as HTMLInputElement;
  const labels = 'labels' in input && input.labels ? Array.from(input.labels).map((l) => l.textContent || '').join(' ') : '';
  const hint = [attr(el, 'name'), attr(el, 'id'), attr(el, 'aria-label'), attr(el, 'placeholder'), attr(el, 'autocomplete'), labels.toLowerCase()].join(' ');
  const textTypes = ['', 'text', 'search', 'email', 'url', 'tel', 'password', 'number'];
  const editable =
    (tag === 'input' && textTypes.includes(type)) || tag === 'textarea' || (el as HTMLElement).isContentEditable === true || attr(el, 'role') === 'textbox';
  const sensitive =
    (tag === 'input' && type === 'password') ||
    /(current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp)/.test(attr(el, 'autocomplete')) ||
    /(pass(word|code|phrase)?|pwd|otp|one[-_ ]?time|2fa|mfa|totp|verification[-_ ]?code|security[-_ ]?code|\bpin\b|cvv|cvc|card number|ssn|secret)/.test(hint);
  const label = (
    control.getAttribute('aria-label') ||
    (control as HTMLElement).innerText ||
    (control as HTMLInputElement).value ||
    control.getAttribute('title') ||
    ''
  )
    .trim()
    .slice(0, 120);
  return {
    tag,
    type,
    role: attr(control, 'role'),
    label: type === 'password' ? '' : label,
    inForm: Boolean(form),
    isSubmit: (ctag === 'button' && (ctype === 'submit' || (!ctype && Boolean(form)))) || (ctag === 'input' && (ctype === 'submit' || ctype === 'image')),
    href: link ? link.href : undefined,
    linkTarget: link ? link.target || undefined : undefined,
    download: Boolean(link && link.hasAttribute('download')),
    fileInput: tag === 'input' && type === 'file',
    sensitive,
    editable,
    multiline: tag === 'textarea' || (el as HTMLElement).isContentEditable === true,
  };
};

export async function inspectLocator(locator: Locator): Promise<ElementInfo> {
  return locator.evaluate(describe, undefined, { timeout: 5000 });
}

export async function inspectHandle(handle: ElementHandle): Promise<ElementInfo> {
  return handle.evaluate(describe);
}

const SENSITIVE_CHECK = (el: Element): boolean => {
  const attr = (n: string) => (el.getAttribute(n) || '').toLowerCase();
  const input = el as HTMLInputElement;
  if (el.tagName.toLowerCase() === 'input' && attr('type') === 'password') return true;
  if (/(current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp)/.test(attr('autocomplete'))) return true;
  const labels = 'labels' in input && input.labels ? Array.from(input.labels).map((l) => l.textContent || '').join(' ') : '';
  const hint = [attr('name'), attr('id'), attr('aria-label'), attr('placeholder'), labels.toLowerCase()].join(' ');
  return /(pass(word|code|phrase)?|pwd|otp|one[-_ ]?time|2fa|mfa|totp|verification[-_ ]?code|security[-_ ]?code|\bpin\b|cvv|cvc|card number|ssn|secret)/.test(hint);
};

/** True if the element is (or may be) a secret field. Errors count as sensitive. */
export async function isSensitiveField(locator: Locator): Promise<boolean> {
  try {
    return await locator.evaluate(SENSITIVE_CHECK, undefined, { timeout: 2000 });
  } catch {
    return true;
  }
}
