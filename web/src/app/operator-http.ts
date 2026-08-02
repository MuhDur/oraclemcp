const MAX_OPERATOR_ERROR_BODY_BYTES = 16 * 1024;
const MAX_OPERATOR_ERROR_DETAIL_CHARS = 512;
export const MAX_OPERATOR_SUCCESS_BODY_BYTES = 8 * 1024 * 1024;
export const DEFAULT_OPERATOR_REQUEST_TIMEOUT_MS = 15_000;

export type OperatorHttpClientErrorKind = "body_too_large" | "cancelled" | "timeout";

/** A bounded client-side transport failure, distinct from an operator outcome. */
export class OperatorHttpClientError extends Error {
  readonly kind: OperatorHttpClientErrorKind;

  constructor(kind: OperatorHttpClientErrorKind, message: string) {
    super(message);
    this.name = "OperatorHttpClientError";
    this.kind = kind;
  }
}

export type OperatorRequestOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
};

type OperatorRequestAbortKind = "cancelled" | "timeout";

type OperatorResponseLifetime = {
  aborted: Promise<OperatorRequestAbortKind>;
  abortKind: () => OperatorRequestAbortKind | null;
  finish: () => void;
};

const operatorResponseLifetimes = new WeakMap<Response, OperatorResponseLifetime>();

/** Fetch with a caller abort and an independent absolute browser-side deadline. */
export async function fetchOperatorRequest(
  input: RequestInfo | URL,
  init: RequestInit = {},
  options: OperatorRequestOptions = {}
): Promise<Response> {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? DEFAULT_OPERATOR_REQUEST_TIMEOUT_MS;
  let abortKind: OperatorRequestAbortKind | null = null;
  let active = true;
  let timeout: ReturnType<typeof globalThis.setTimeout> | undefined;
  let resolveAbort!: (kind: OperatorRequestAbortKind) => void;
  const aborted = new Promise<OperatorRequestAbortKind>((resolve) => {
    resolveAbort = resolve;
  });
  const handleCallerAbort = (): void => abort("cancelled");
  const cleanup = (): void => {
    if (timeout !== undefined) {
      globalThis.clearTimeout(timeout);
    }
    options.signal?.removeEventListener("abort", handleCallerAbort);
  };
  const finish = (): void => {
    if (!active) {
      return;
    }
    active = false;
    cleanup();
  };
  const abort = (kind: OperatorRequestAbortKind): void => {
    if (!active || abortKind) {
      return;
    }
    abortKind = kind;
    active = false;
    controller.abort();
    cleanup();
    resolveAbort(kind);
  };
  if (options.signal?.aborted) {
    abort("cancelled");
  } else {
    options.signal?.addEventListener("abort", handleCallerAbort, { once: true });
  }
  if (active) {
    timeout = globalThis.setTimeout(() => abort("timeout"), Math.max(0, timeoutMs));
  }

  try {
    const response = await Promise.race([
      fetch(input, { ...init, signal: controller.signal }),
      aborted.then((kind) => {
        throw requestAbortError(kind);
      })
    ]);
    if (response.body) {
      operatorResponseLifetimes.set(response, {
        aborted,
        abortKind: () => abortKind,
        finish
      });
    } else {
      finish();
    }
    return response;
  } catch (error) {
    finish();
    if (error instanceof OperatorHttpClientError) {
      throw error;
    }
    if (abortKind) {
      throw requestAbortError(abortKind);
    }
    throw error;
  }
}

/**
 * Decode an operator response without leaking a raw `Response.json()` syntax
 * error when a proxy or failed server returns HTML, plain text, or no body.
 * Successful operator payloads retain the normal JSON path. Error bodies are
 * read through a byte cap because their contents are untrusted diagnostics,
 * not API data.
 */
export async function parseOperatorHttpResponse(
  response: Response,
  maxSuccessBytes = MAX_OPERATOR_SUCCESS_BODY_BYTES
): Promise<unknown> {
  if (response.ok) {
    const { text } = await boundedResponseText(
      response,
      maxSuccessBytes,
      "throw"
    );
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return {
        error: "invalid_operator_response",
        message: `operator returned an empty or non-JSON response with HTTP ${response.status}`
      };
    }
  }

  const { text, truncated } = await boundedResponseText(
    response,
    MAX_OPERATOR_ERROR_BODY_BYTES,
    "truncate"
  );
  const trimmed = text.trim();
  if (trimmed) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (isRecord(parsed)) {
        return parsed;
      }
    } catch {
      // Fall through to a bounded plain-text diagnostic.
    }
  }

  const normalized = trimmed.replace(/\s+/g, " ").slice(0, MAX_OPERATOR_ERROR_DETAIL_CHARS);
  const statusDetail = response.statusText.trim();
  const detail = normalized || statusDetail || "empty response";
  return {
    error: "operator_http_error",
    message: `operator request failed with HTTP ${response.status}: ${detail}${truncated ? " [truncated]" : ""}`
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export async function boundedResponseText(
  response: Response,
  maxBytes: number,
  overflow: "throw" | "truncate" = "truncate"
): Promise<{ text: string; truncated: boolean }> {
  const lifetime = operatorResponseLifetimes.get(response);
  try {
    const declaredLength = response.headers.get("content-length");
    if (declaredLength && /^\d+$/.test(declaredLength)) {
      const bytes = Number(declaredLength);
      if (Number.isSafeInteger(bytes) && bytes > maxBytes) {
        cancelResponseBody(response);
        if (overflow === "throw") {
          throw bodyTooLarge(maxBytes);
        }
        return { text: "", truncated: true };
      }
    }
    const reader = response.body?.getReader();
    if (!reader) {
      return { text: "", truncated: false };
    }

    const chunks: Uint8Array[] = [];
    let bytes = 0;
    let truncated = false;
    while (true) {
      const next = await readResponseChunk(reader, lifetime);
      if (next.done) {
        break;
      }
      const remaining = maxBytes - bytes;
      if (next.value.byteLength > remaining) {
        if (remaining > 0) {
          chunks.push(next.value.subarray(0, remaining));
          bytes += remaining;
        }
        truncated = true;
        cancelReader(reader);
        if (overflow === "throw") {
          throw bodyTooLarge(maxBytes);
        }
        break;
      }
      chunks.push(next.value);
      bytes += next.value.byteLength;
      if (bytes === maxBytes) {
        const beyondLimit = await readResponseChunk(reader, lifetime);
        truncated = !beyondLimit.done;
        if (truncated) {
          cancelReader(reader);
          if (overflow === "throw") {
            throw bodyTooLarge(maxBytes);
          }
        }
        break;
      }
    }

    const combined = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { text: new TextDecoder().decode(combined), truncated };
  } catch (error) {
    const abortKind = lifetime?.abortKind();
    if (abortKind) {
      throw requestAbortError(abortKind);
    }
    throw error;
  } finally {
    lifetime?.finish();
    operatorResponseLifetimes.delete(response);
  }
}

async function readResponseChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  lifetime: OperatorResponseLifetime | undefined
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (!lifetime) {
    return reader.read();
  }
  return Promise.race([
    reader.read(),
    lifetime.aborted.then((kind) => {
      cancelReader(reader);
      throw requestAbortError(kind);
    })
  ]);
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  void reader.cancel().catch(() => undefined);
}

function cancelResponseBody(response: Response): void {
  void response.body?.cancel().catch(() => undefined);
}

function requestAbortError(kind: OperatorRequestAbortKind): OperatorHttpClientError {
  return new OperatorHttpClientError(
    kind,
    kind === "timeout" ? "operator request timed out" : "operator request was cancelled"
  );
}

function bodyTooLarge(maxBytes: number): OperatorHttpClientError {
  return new OperatorHttpClientError(
    "body_too_large",
    `operator response exceeded the ${maxBytes}-byte browser limit`
  );
}
