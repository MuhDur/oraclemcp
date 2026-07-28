const MAX_OPERATOR_ERROR_BODY_BYTES = 16 * 1024;
const MAX_OPERATOR_ERROR_DETAIL_CHARS = 512;

/**
 * Decode an operator response without leaking a raw `Response.json()` syntax
 * error when a proxy or failed server returns HTML, plain text, or no body.
 * Successful operator payloads retain the normal JSON path. Error bodies are
 * read through a byte cap because their contents are untrusted diagnostics,
 * not API data.
 */
export async function parseOperatorHttpResponse(response: Response): Promise<unknown> {
  if (response.ok) {
    try {
      return (await response.json()) as unknown;
    } catch {
      return {
        error: "invalid_operator_response",
        message: `operator returned an empty or non-JSON response with HTTP ${response.status}`
      };
    }
  }

  const { text, truncated } = await boundedResponseText(
    response,
    MAX_OPERATOR_ERROR_BODY_BYTES
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

async function boundedResponseText(
  response: Response,
  maxBytes: number
): Promise<{ text: string; truncated: boolean }> {
  const reader = response.body?.getReader();
  if (!reader) {
    return { text: "", truncated: false };
  }

  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = false;
  while (true) {
    const next = await reader.read();
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
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(next.value);
    bytes += next.value.byteLength;
    if (bytes === maxBytes) {
      const beyondLimit = await reader.read();
      truncated = !beyondLimit.done;
      if (truncated) {
        await reader.cancel().catch(() => undefined);
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
}
