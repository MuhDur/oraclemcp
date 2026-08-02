export type ExplorerCacheStatus = "hit" | "miss" | "stale" | "bypass";

export type ExplorerMetadataCacheKey = {
  db_fingerprint: string;
  profile: string;
  user: string;
  visible_schema: string;
  serialization_contract_version: number;
};

export type ExplorerCachedResult<T> = {
  value: T;
  status: ExplorerCacheStatus;
  bytes: number;
  cacheKey: string;
};

type CacheEntry = {
  value: unknown;
  bytes: number;
  expiresAt: number;
  lastAccessed: number;
};

type CacheLoad = {
  generation: number;
  promise: Promise<ExplorerCachedResult<unknown>>;
};

const CACHE_TTL_MS = 60_000;
const CACHE_MAX_BYTES = 512_000;
const CACHE_MAX_ENTRIES = 64;
const cache = new Map<string, CacheEntry>();
const loads = new Map<string, CacheLoad>();
let cacheBytes = 0;
let generation = 0;

export async function cachedExplorerMetadata<T>(
  scope: ExplorerMetadataCacheKey,
  slot: string,
  load: () => Promise<T>
): Promise<ExplorerCachedResult<T>> {
  const cacheKey = explorerCacheKey(scope, slot);
  const now = Date.now();
  const existing = cache.get(cacheKey);
  if (existing) {
    if (existing.expiresAt > now) {
      existing.lastAccessed = now;
      return {
        value: existing.value as T,
        status: "hit",
        bytes: existing.bytes,
        cacheKey
      };
    }
    removeEntry(cacheKey);
  }

  const pending = loads.get(cacheKey);
  if (pending && pending.generation === generation) {
    return pending.promise as Promise<ExplorerCachedResult<T>>;
  }

  const loadGeneration = generation;
  const promise = (async (): Promise<ExplorerCachedResult<T>> => {
    const value = await load();
    const bytes = jsonBytes(value);
    if (bytes > CACHE_MAX_BYTES || loadGeneration !== generation) {
      return { value, status: "bypass", bytes, cacheKey };
    }

    const loadedAt = Date.now();
    removeEntry(cacheKey);
    cache.set(cacheKey, {
      value,
      bytes,
      expiresAt: loadedAt + CACHE_TTL_MS,
      lastAccessed: loadedAt
    });
    cacheBytes += bytes;
    trimCache();
    return { value, status: existing ? "stale" : "miss", bytes, cacheKey };
  })();
  loads.set(cacheKey, { generation: loadGeneration, promise });

  try {
    return await promise;
  } finally {
    if (loads.get(cacheKey)?.promise === promise) {
      loads.delete(cacheKey);
    }
  }
}

export function clearExplorerMetadataCache(): void {
  generation += 1;
  cache.clear();
  loads.clear();
  cacheBytes = 0;
}

export function explorerMetadataCacheSummary(): { entries: number; bytes: number } {
  trimCache();
  return { entries: cache.size, bytes: cacheBytes };
}

function explorerCacheKey(scope: ExplorerMetadataCacheKey, slot: string): string {
  return JSON.stringify({
    db_fingerprint: scope.db_fingerprint,
    profile: scope.profile,
    user: scope.user,
    visible_schema: scope.visible_schema,
    serialization_contract_version: scope.serialization_contract_version,
    slot
  });
}

function removeEntry(cacheKey: string): void {
  const existing = cache.get(cacheKey);
  if (!existing) {
    return;
  }
  cache.delete(cacheKey);
  cacheBytes = Math.max(0, cacheBytes - existing.bytes);
}

function trimCache(): void {
  const now = Date.now();
  for (const [cacheKey, entry] of cache) {
    if (entry.expiresAt <= now) {
      removeEntry(cacheKey);
    }
  }
  while (cache.size > CACHE_MAX_ENTRIES || cacheBytes > CACHE_MAX_BYTES) {
    const oldest = [...cache.entries()].sort(
      (a, b) => a[1].lastAccessed - b[1].lastAccessed
    )[0];
    if (!oldest) {
      break;
    }
    removeEntry(oldest[0]);
  }
}

function jsonBytes(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}
