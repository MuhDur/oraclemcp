"""Normalize volatile MCP fields before comparing W4 golden values."""

import re


VOLATILE_KEYS = {
    "timestamp", "created_at", "updated_at", "started_at", "finished_at",
    "request_id", "correlation_id", "session_id", "scn", "duration_ms",
    "elapsed_ms", "elapsed_seconds", "run_id", "trace_id", "generated_at",
}
RUN_ID = re.compile(r"W4[0-9]{4}[A-F0-9]{6}")
UNTRUSTED_MARKER = re.compile(r"untrusted-user-data-[0-9a-f]{8,}")


def scrub(value, path=()):
    if isinstance(value, dict):
        semantic_row = "rows" in path or "values" in path
        return {key: "<volatile>" if not semantic_row and key.lower() in VOLATILE_KEYS
                else scrub(item, path + (key,))
                for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, path) for item in value]
    if isinstance(value, str):
        return UNTRUSTED_MARKER.sub("untrusted-user-data-<volatile>",
                                    RUN_ID.sub("<run_id>", value))
    return value
