import { OperatorHttpClientError } from "./operator-http";
import type { DashboardSession } from "./operator-session";

type OperatorGetCacheEntry = {
  etag: string;
  value: unknown;
  bytes: number;
  expiresAt: number;
};

export type OperatorGetCachePolicy = {
  maxEntries: number;
  maxBytes: number;
  ttlMs: number;
};

const DEFAULT_POLICY: OperatorGetCachePolicy = {
  maxEntries: 64,
  maxBytes: 4 * 1024 * 1024,
  ttlMs: 5 * 60_000
};

/** Session-scoped deterministic LRU for conditional operator GETs. */
export class OperatorGetCache {
  private readonly entries = new Map<string, OperatorGetCacheEntry>();
  private totalBytes = 0;

  constructor(
    private readonly policy: OperatorGetCachePolicy = DEFAULT_POLICY,
    private readonly now: () => number = Date.now
  ) {}

  get(path: string, epoch: number): { etag: string; value: unknown } | undefined {
    this.pruneExpired();
    const key = cacheKey(path, epoch);
    const entry = this.entries.get(key);
    if (!entry) {
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return { etag: entry.etag, value: entry.value };
  }

  set(path: string, epoch: number, etag: string, value: unknown): void {
    this.pruneExpired();
    const key = cacheKey(path, epoch);
    const bytes = jsonBytes(value) + new TextEncoder().encode(`${key}\0${etag}`).byteLength;
    this.remove(key);
    if (bytes > this.policy.maxBytes || this.policy.maxEntries < 1) {
      return;
    }
    this.entries.set(key, {
      etag,
      value,
      bytes,
      expiresAt: this.now() + this.policy.ttlMs
    });
    this.totalBytes += bytes;
    while (
      this.entries.size > this.policy.maxEntries ||
      this.totalBytes > this.policy.maxBytes
    ) {
      const oldestKey = this.entries.keys().next().value as string | undefined;
      if (!oldestKey) {
        break;
      }
      this.remove(oldestKey);
    }
  }

  clear(): void {
    this.entries.clear();
    this.totalBytes = 0;
  }

  summary(): { entries: number; bytes: number } {
    this.pruneExpired();
    return { entries: this.entries.size, bytes: this.totalBytes };
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.remove(key);
      }
    }
  }

  private remove(key: string): void {
    const entry = this.entries.get(key);
    if (!entry) {
      return;
    }
    this.entries.delete(key);
    this.totalBytes = Math.max(0, this.totalBytes - entry.bytes);
  }
}

export class OperatorSessionCache {
  private readonly cache = new OperatorGetCache();
  private epoch = 0;
  private authority: string | null = null;

  activate(session: DashboardSession): { changed: boolean; epoch: number } {
    const authority = JSON.stringify([
      session.csrf_token,
      session.csrf_header,
      session.action_ticket_header,
      session.expires_unix,
      session.action_tickets.map(({ method, path, ticket }) => [method, path, ticket])
    ]);
    const changed = authority !== this.authority;
    if (changed) {
      this.authority = authority;
      this.epoch += 1;
      this.cache.clear();
    }
    return { changed, epoch: this.epoch };
  }

  clear(): void {
    this.authority = null;
    this.epoch += 1;
    this.cache.clear();
  }

  currentEpoch(): number {
    return this.epoch;
  }

  get(path: string, epoch: number): { etag: string; value: unknown } | undefined {
    return this.cache.get(path, epoch);
  }

  set(path: string, epoch: number, etag: string, value: unknown): void {
    this.cache.set(path, epoch, etag, value);
  }

  assertCurrent(epoch: number): void {
    if (epoch !== this.epoch) {
      throw new OperatorHttpClientError(
        "cancelled",
        "operator request was cancelled because the dashboard session changed"
      );
    }
  }

  summary(): { entries: number; bytes: number; epoch: number } {
    return { ...this.cache.summary(), epoch: this.epoch };
  }
}

function cacheKey(path: string, epoch: number): string {
  return `${epoch}\0${path}`;
}

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}
