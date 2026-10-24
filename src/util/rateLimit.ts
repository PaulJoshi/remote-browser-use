import { type Clock, systemClock } from './clock.js';

interface Bucket {
  tokens: number;
  updated: number;
}

/** Simple token bucket keyed by an arbitrary string. */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly capacity: number,
    private readonly refillPerMinute: number,
    private readonly clock: Clock = systemClock,
  ) {}

  take(key: string, cost = 1): boolean {
    const now = this.clock.now();
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, updated: now };
    const elapsedMin = (now - bucket.updated) / 60_000;
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedMin * this.refillPerMinute);
    bucket.updated = now;
    const ok = bucket.tokens >= cost;
    if (ok) bucket.tokens -= cost;
    this.buckets.set(key, bucket);
    if (this.buckets.size > 5000) this.prune(now);
    return ok;
  }

  private prune(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updated > 10 * 60_000) this.buckets.delete(key);
    }
  }
}
