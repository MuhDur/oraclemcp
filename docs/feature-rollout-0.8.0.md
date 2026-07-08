# 0.8.0 Feature Rollout Defaults

This page lists the default posture and opt-in path for the new 0.8.0 surfaces.
Defaults are deliberately narrow: the server exposes new capability only when a
profile, request, or transport explicitly asks for it.

| Surface | Default | Enable or disable | Safety rationale |
|---|---|---|---|
| Streaming `oracle_query` delivery | Off per request. Cursor pagination remains available by default. `oracle_capabilities.tool_features.streaming` is `false` on stdio and `true` only when HTTP transport is available for SSE chunk frames. | Enable for one read with `streaming = true`. Disable by omitting it or setting `false`. Do not combine with `export` or `as_of`. | Changes delivery only; the same statement is classified once before any I/O, row/byte caps still apply, and chunks are resumable pages. |
| Statement cache / statement-shape reuse | On where the driver and pool-backed reads use it. The server-side documented default is `[profiles.pool].statement_cache_size = 50`. | Leave omitted for the default. Tune per profile with `[profiles.pool].statement_cache_size` when diagnosing cache pressure. There is no agent-facing toggle. | The cache is below the classifier and cannot widen SQL authority. DDL shape changes heal down by invalidating/repreparing rather than trusting stale decode. |
| Remote Streamable HTTP bind | Off. `[http].allow_remote` defaults to `false`; loopback remains the normal bind boundary. | Set `[http].allow_remote = true` or start one process with `ORACLEMCP_HTTP_ALLOW_REMOTE=1`. Disable by removing both. | Non-loopback binding is an operator action. It still does not authenticate clients; use OAuth, mTLS, client credentials, or an explicit development `--allow-no-auth`. |
| OCI IAM database-token source | Off per profile. `[profiles.oci].use_iam_token` defaults to `false`; `token_env`, `token_file`, and `token_exec` default to unset. | Set `use_iam_token = true` and configure at most one source, or rely on `ORACLEMCP_IAM_TOKEN`. Disable by setting `use_iam_token = false` or removing the source fields. | Tokens are resolved transiently, never logged, and refused over non-TCPS. `token_exec` is an argv array with no shell interpretation, a timeout, and an output cap. |
| Pipelining | No force-enable config. Unknown until a live connection reports `connection.server_features.supports_pipelining`. | Upgrade to 0.8.0 and let the driver/server negotiation decide. There is no profile key that can force pipelining on an unsupported server. | The server treats pipelining as a negotiated transport capability, not an authorization decision. Unsupported or unknown support degrades to the ordinary request path. |

Related config reference:

- [`configuration.md`](configuration.md)
- [`upgrading-to-0.8.0.md`](upgrading-to-0.8.0.md)
- [`downgrading-0.8.0-to-0.7.2.md`](downgrading-0.8.0-to-0.7.2.md)
