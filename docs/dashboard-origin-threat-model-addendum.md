# Dashboard Origin Threat-Model Addendum

This addendum records the A5 security review for the dashboard origin change.
It covers the browser-only dashboard surface: `/dashboard/pair`,
`/dashboard/session`, and the browser operator routes under `/operator/v1`.
It does not change the MCP HTTP bearer/mTLS contract or the fail-closed SQL
guard invariant described in [`threat-model.md`](threat-model.md).

## Boundary

A hostile web page can make a browser try to reach a loopback dashboard and can
benefit from ambient browser credentials such as cookies or client
certificates. It cannot read same-origin dashboard responses unless it already
has a same-origin script execution bug. Loopback reachability is therefore not
authentication, and a valid transport principal does not by itself prove that a
browser request was initiated by the dashboard UI.

The implementation keeps that distinction explicit:

- `/dashboard/pair` requires loopback, a live listener-bound one-time ticket,
  a same-origin POST, and a body-only code.
- Authenticated dashboard POST actions require a same-origin browser request, a
  dashboard session cookie, the session CSRF token, and a route-scoped action
  ticket.
- The dashboard Workbench still forwards to the same guarded MCP tools
  (`oracle_preview_sql`, `oracle_query`, `oracle_execute`) instead of gaining a
  browser-only SQL execution path.

## Fetch-First and Strict Origin

A5 fixed the browser breakage by making mutating dashboard actions
fetch-first: the dashboard client sends same-origin `fetch()` requests to
relative operator paths with `Content-Type: application/json`. That is a
transport-shape constraint, not a relaxation. A plain HTML form cannot create an
`application/json` POST with the required dashboard headers, while default-mode
same-origin `fetch()` gives the browser a concrete Origin for the dashboard
origin even when the rest of the dashboard keeps `Referrer-Policy:
no-referrer`.

The server still enforces strict Origin. For browser POSTs,
`enforce_dashboard_post_headers` fails closed when the Origin header is absent,
malformed, or not the same scheme/authority as `Host`. For all dashboard
operator requests, `enforce_dashboard_get_headers` runs before any authenticated
principal is trusted, so an ambient cookie or ambient mTLS client certificate
does not bypass the browser-origin check. `Sec-Fetch-Site` is only a narrowing
signal: if present and not `same-origin` or `none`, it rejects; it never
authorizes a request whose Origin failed.

This preserves the fail-closed posture because the change removes the broken
form-navigation shape rather than accepting a weaker origin proof. Requests
that do not carry a concrete same-origin Origin on browser POST still fail
before action dispatch.

## Ambient Credentials Versus Bearers

The agent-mail reference usefully demonstrated the JSON-fetch shape: mutating
browser actions use same-origin `fetch()` plus `Content-Type: application/json`,
so they avoid the `Origin: null` form-navigation trap. oraclemcp copies that
transport shape, but deliberately keeps a stricter Origin rule.

That difference is required because the dashboard session is an ambient
browser credential. A paired dashboard uses an HttpOnly cookie, and some
deployments may also have browser-attached client certificates. A malicious page
can cause a browser to attach those credentials even though it cannot read the
dashboard origin. By contrast, a stateless bearer token is supplied by the
client code that possesses it. Ambient browser credentials therefore demand a
hard Origin gate before they are trusted; the server must not downgrade to
"Origin or fetch metadata looks plausible."

## `Origin: null`

The literal header `Origin: null` is never accepted. It is an opaque-origin
signal produced by contexts such as sandboxed documents, `data:` or `file:`
origins, and the old no-referrer form-navigation pairing path. An opaque origin
does not name the dashboard scheme, host, and port, so a fail-closed dashboard
cannot treat it as same-origin proof.

The implementation rejects it mechanically, not by a special-case allowlist:
`origin_matches_host` accepts only `http://` or `https://` origins whose
authority equals the request `Host`. The string `null` has no scheme and
authority, so it fails. Accepting `Origin: null` when `Sec-Fetch-Site:
same-origin` is present would make the auxiliary fetch metadata vouch for an
opaque origin; A5 deliberately does not do that.

The regression tests pin both sensitive cases:

- `malicious_page_cannot_trigger_dashboard_gated_action` verifies that an
  operator POST with `Origin: null`, JSON, a valid cookie, CSRF token, and
  action ticket is refused before dispatch.
- `served_dashboard_pairing_refuses_origin_null_without_consuming_ticket`
  verifies that a pairing POST with `Origin: null` does not mint a cookie and
  does not consume the one-time ticket.

## CSRF Layers

The primary browser CSRF layer for mutating dashboard actions is
`Content-Type: application/json` plus same-origin `fetch()`. A hostile site can
submit forms to loopback, but it cannot make a normal HTML form satisfy the JSON
content type and custom dashboard headers. The dashboard client uses
`credentials: "same-origin"` and attaches the CSRF and action-ticket headers
only after reading `/dashboard/session` from the dashboard origin.

The existing layers still matter:

- The strict Origin check proves the browser request came from the dashboard
  origin before ambient credentials are trusted.
- The dashboard cookie is `HttpOnly` and `SameSite=Strict`; it reduces ambient
  cross-site sending and prevents page script from reading the session id, but
  it is not treated as the only CSRF boundary.
- The CSRF token is session-bound and returned only through the same-origin
  session view.
- The action ticket is bound to method and path. A ticket for one operator POST
  route cannot be replayed to another route, and a missing or mismatched ticket
  fails the action before dispatch.

This is defense in depth. JSON fetch shape blocks plain form CSRF, Origin
rejects forged browser origins, SameSite reduces ambient cookie exposure,
HttpOnly protects the raw session cookie from ordinary page script, and the
CSRF/action-ticket pair binds an authenticated dashboard session to a specific
route.

## Pairing Contract

The pairing contract is unchanged:

- `oraclemcp dashboard` prints a secret-free `/dashboard/pair` URL plus a
  separate one-time code.
- The code is accepted only from the pairing form POST body field; it is never
  read from the query string or fragment.
- `/dashboard/pair?ticket=...` is refused before body parsing or ticket
  exchange, so the named ticket is not consumed.
- A literal `Origin: null` pairing POST is refused before body exchange, so it
  also does not consume the ticket.
- The ticket expires after 60 seconds and `exchange_ticket` removes the ticket
  file before minting the dashboard session, making it single-use.

The pairing page alone uses `Referrer-Policy: same-origin` so the script-free
form POST carries a concrete same-origin Origin. That does not leak a secret
because the page URL and form action are secret-free by design. The successful
pairing redirect and the rest of the dashboard keep the dashboard-wide
`Referrer-Policy: no-referrer`.

## Deliberate Test Updates

A5 changed only the assertions that had encoded the broken browser contract.
Tests that previously expected the pairing form response to carry
`Referrer-Policy: no-referrer` now expect `same-origin` on the secret-free form
page and still expect `no-referrer` on the POST redirect/dashboard response.
The change is deliberate because the pairing form is the only form-navigation
POST the dashboard keeps; authenticated actions moved to JSON fetch.

The same test set now records the non-negotiable refusal cases: query-string
pairing secrets are refused without consuming the ticket, literal
`Origin: null` is refused without consuming the ticket, and authenticated
dashboard action POSTs with a malicious or opaque origin do not reach dispatch.
