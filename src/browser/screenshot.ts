import type { Frame, Locator } from 'playwright-core';
import { PNG } from 'pngjs';
import type { Tab } from './manager.js';

export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export class ScreenshotDenied extends Error {}

const MASK_RGB = [107, 114, 128] as const;
const MAX_FULL_PAGE_HEIGHT = 12_000;

interface MaskSet {
  frames: Set<Frame>;
  rects: Rect[];
}

/** Outermost frames the client may not see, with their on-screen rectangles. Fails closed if a frame cannot be located. */
async function collectMasks(tab: Tab, isAllowed: (f: Frame) => boolean): Promise<MaskSet> {
  const frames = new Set<Frame>();
  const rects: Rect[] = [];
  for (const frame of tab.page.frames()) {
    if (frame === tab.page.mainFrame() || frame.isDetached() || isAllowed(frame)) continue;
    let ancestor = frame.parentFrame();
    let coveredByAncestor = false;
    while (ancestor && ancestor !== tab.page.mainFrame()) {
      if (!isAllowed(ancestor)) coveredByAncestor = true;
      ancestor = ancestor.parentFrame();
    }
    frames.add(frame);
    if (coveredByAncestor) continue;
    let box: Rect | null;
    try {
      const element = await frame.frameElement();
      box = await element.boundingBox();
      await element.dispose();
    } catch {
      if (frame.isDetached()) continue;
      throw new ScreenshotDenied('An unshared frame could not be located on screen, so the screenshot was withheld.');
    }
    if (box) rects.push(box);
  }
  return { frames, rects };
}

function sameFrames(a: Set<Frame>, b: Set<Frame>): boolean {
  if (a.size !== b.size) return false;
  for (const f of a) if (!b.has(f)) return false;
  return true;
}

function paint(png: PNG, rect: Rect, pad = 2): void {
  const x0 = Math.max(0, Math.floor(rect.x - pad));
  const y0 = Math.max(0, Math.floor(rect.y - pad));
  const x1 = Math.min(png.width, Math.ceil(rect.x + rect.width + pad));
  const y1 = Math.min(png.height, Math.ceil(rect.y + rect.height + pad));
  for (let y = y0; y < y1; y++) {
    for (let x = x0; x < x1; x++) {
      const i = (y * png.width + x) * 4;
      const stripe = ((x + y) >> 4) % 2 === 0;
      png.data[i] = stripe ? MASK_RGB[0] : MASK_RGB[0] + 20;
      png.data[i + 1] = stripe ? MASK_RGB[1] : MASK_RGB[1] + 20;
      png.data[i + 2] = stripe ? MASK_RGB[2] : MASK_RGB[2] + 20;
      png.data[i + 3] = 255;
    }
  }
}

function crop(png: PNG, rect: Rect): PNG {
  const x0 = Math.max(0, Math.floor(rect.x));
  const y0 = Math.max(0, Math.floor(rect.y));
  const w = Math.max(1, Math.min(png.width - x0, Math.ceil(rect.width)));
  const h = Math.max(1, Math.min(png.height - y0, Math.ceil(rect.height)));
  const out = new PNG({ width: w, height: h });
  for (let y = 0; y < h; y++) png.data.copy(out.data, y * w * 4, ((y0 + y) * png.width + x0) * 4, ((y0 + y) * png.width + x0 + w) * 4);
  return out;
}

/** Area-averaging downscale. */
export function downscale(png: PNG, maxWidth: number): PNG {
  if (png.width <= maxWidth) return png;
  const scale = png.width / maxWidth;
  const w = maxWidth;
  const h = Math.max(1, Math.round(png.height / scale));
  const out = new PNG({ width: w, height: h });
  for (let y = 0; y < h; y++) {
    const sy0 = Math.floor(y * scale);
    const sy1 = Math.min(png.height, Math.max(sy0 + 1, Math.floor((y + 1) * scale)));
    for (let x = 0; x < w; x++) {
      const sx0 = Math.floor(x * scale);
      const sx1 = Math.min(png.width, Math.max(sx0 + 1, Math.floor((x + 1) * scale)));
      let r = 0,
        g = 0,
        b = 0,
        a = 0;
      const n = (sy1 - sy0) * (sx1 - sx0);
      for (let sy = sy0; sy < sy1; sy++) {
        let i = (sy * png.width + sx0) * 4;
        for (let sx = sx0; sx < sx1; sx++, i += 4) {
          r += png.data[i]!;
          g += png.data[i + 1]!;
          b += png.data[i + 2]!;
          a += png.data[i + 3]!;
        }
      }
      const o = (y * w + x) * 4;
      out.data[o] = r / n;
      out.data[o + 1] = g / n;
      out.data[o + 2] = b / n;
      out.data[o + 3] = a / n;
    }
  }
  return out;
}

export interface ScreenshotOptions {
  fullPage?: boolean;
  target?: Locator;
  maxWidth: number;
}

export interface ScreenshotResult {
  png: Buffer;
  width: number;
  height: number;
  maskedFrames: number;
  note?: string;
}

/**
 * Capture the tab and paint over every unshared frame directly in the image
 * bytes (not with page DOM overlays, which a hostile page could remove).
 * Frame geometry is sampled before and after capture; if the set of unshared
 * frames changes during capture the screenshot is retried once, then withheld.
 */
export async function screenshotTab(tab: Tab, isAllowed: (f: Frame) => boolean, opts: ScreenshotOptions): Promise<ScreenshotResult> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const before = await collectMasks(tab, isAllowed);
    if (opts.fullPage && before.frames.size > 0) {
      throw new ScreenshotDenied('Full-page screenshots are unavailable while this page contains frames that are not shared with you. Take a viewport screenshot instead.');
    }
    let targetBox: Rect | null = null;
    if (opts.target) {
      await opts.target.scrollIntoViewIfNeeded({ timeout: 5000 });
      targetBox = await opts.target.boundingBox({ timeout: 5000 });
      if (!targetBox) throw new ScreenshotDenied('The target element is not visible.');
    }
    const raw = await tab.page.screenshot({ type: 'png', scale: 'css', fullPage: Boolean(opts.fullPage), caret: 'hide', timeout: 15_000 });
    const after = await collectMasks(tab, isAllowed);
    if (!sameFrames(before.frames, after.frames)) continue;
    let png: PNG = PNG.sync.read(raw);
    for (const rect of [...before.rects, ...after.rects]) paint(png, rect);
    let note: string | undefined;
    if (targetBox) png = crop(png, targetBox);
    if (opts.fullPage && png.height > MAX_FULL_PAGE_HEIGHT) {
      png = crop(png, { x: 0, y: 0, width: png.width, height: MAX_FULL_PAGE_HEIGHT });
      note = `Full page was cropped to the first ${MAX_FULL_PAGE_HEIGHT}px.`;
    }
    png = downscale(png, opts.maxWidth);
    return { png: PNG.sync.write(png), width: png.width, height: png.height, maskedFrames: before.frames.size, note };
  }
  throw new ScreenshotDenied('Frames on the page kept changing during capture, so the screenshot was withheld. Try again.');
}
