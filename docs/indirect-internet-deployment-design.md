# Indirect Internet-facing deployment design

**Status:** design only; no runtime, DNS, Cloudflare, Tailscale, secret, or production change is authorized by this document.

**Decision:** recommend a Cloudflare-first hybrid: Tunnel + Access for native clients, a deliberately small OAuth-protected Remote MCP surface through Tunnel, and a supported Tailscale private-native alternative for peers who operate a tailnet.

**Evidence date:** 2026-08-12. “Verified” means current source or the primary documentation linked in [Sources](#sources); “recommendation” is an architectural decision for a future implementation.

## Decision and constraints

Punaro must not gain a direct public listener, a router port-forward, NAT dependence, or a public copy of its trusted-LAN HTTP profile. Cloudflare Tunnel is the primary edge because its connector makes outbound connections and maps a hostname to a local service without an inbound host port ([Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)). Tailscale is a supported private-native alternative for peers who choose it; its grants are deny-by-default and can constrain source, destination, and port ([Tailscale grants](https://tailscale.com/docs/reference/syntax/grants)).

The decisive compatibility constraint is that hosted connectors originate from vendor cloud infrastructure, not the user’s laptop. Claude says this explicitly for every remote-connector surface, including Claude Desktop, and requires the endpoint to be reachable from Anthropic’s cloud over the public Internet ([Claude remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)). ChatGPT also uses remote MCP, but current OpenAI documentation now offers **Secure MCP Tunnel** for private developer-mode connections: an operator-run `tunnel-client` makes outbound HTTPS long-polls to an OpenAI-hosted endpoint and forwards work to the private MCP server ([OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)). That is a supported product tunnel, not ChatGPT joining a tailnet or running `cloudflared`. Neither hosted client is documented to join a tailnet, inject arbitrary Cloudflare Access service-token headers, or maintain a tenant-specific Access browser session on background requests. **Do not design around those unsupported behaviors.**

Cloudflare’s current documentation also describes **Access OAuth** for protected resources: standards-based resource/authorization-server discovery, dynamic client registration, authorization code with PKCE, refresh, and revocation for coding agents ([Cloudflare coding-agent authentication](https://developers.cloudflare.com/cloudflare-one/access-controls/authenticate-agents/)). That is materially different from browser-cookie Access and header-pair service auth. It creates a viable **option D admission flow**, but the documented Access token contract is not proof of Punaro’s required RS256/`kid`/exact-audience/scope/project-grant token. Treat it as a compatibility-gated admission or token-exchange candidate, not a silent replacement for Punaro authorization and not evidence that hosted clients can inject service-token headers.

Accordingly, the base recommendation is a hybrid endpoint split: hosted MCP is public at the network edge and protected by a Punaro-owned standards-based OAuth authorization server plus Punaro project capabilities. Cloudflare Access OAuth may be added only after both hosted-client tests and an explicit token-exchange/verifier design prove that Access admission cannot bypass Punaro grants. Cloudflare remains valuable for Tunnel origin isolation, TLS, DNS, WAF/rate limiting, and DDoS controls. Browser/session and header-pair Cloudflare Access apply to a *different*, native/operator hostname where their client behavior is known.

| Option | Assessment | Decision |
| --- | --- | --- |
| A. Tunnel + Access for everything | Strong for own interactive/service-token clients, but a browser/session or custom-header Access gate in front of hosted MCP discovery/callback/token calls is not established compatible. It also risks confusing Access identity with Punaro project authority. | Reject as the default shape. It may be used only for the separate native/operator hostname. |
| B. Tailscale-only | Strong private operator/native posture, but hosted ChatGPT and Claude need an Internet-reachable remote endpoint. | Reject for the complete objective; retain for native/operator traffic. |
| C. Cloudflare-first hybrid: Tunnel + Access native, Tunnel + OAuth hosted MCP, supported Tailscale-native alternative | Meets both client populations while retaining small public surface and distinct admission/application authorization. | **Recommended topology.** |
| D. Hybrid C with Cloudflare Access OAuth admission and an explicit Punaro exchange/grant boundary | Cloudflare documents standards-based Access OAuth for coding agents, but its Access resource token is not established compatible with Punaro’s JWT/project-grant contract. A secure design still needs Punaro consent/capability authority and either a narrow token exchange or a reviewed verifier change. | Run only as a constrained milestone-3 spike. Reject if it merely treats an Access token as a Punaro grant or cannot pass both hosted-client and revocation tests. |
| E. Vendor split: OpenAI Secure MCP Tunnel for ChatGPT; Cloudflare Tunnel public OAuth resource for Claude | Removes ChatGPT’s need to reach a public Punaro edge and lets the Claude path be restricted to current Anthropic source ranges, but retains public OAuth/Claude ingress and adds a second tunnel binary, runtime API key, RBAC/workspace association, monitoring, and outage domain. OpenAI documents it for private/developer-mode connections, not public plugin distribution. | Optional hardening profile. Pilot before ChatGPT validation; prefer it for OpenAI-only/private deployments, but do not make it the two-vendor default until operational and authorization equivalence are proven. |

## 1. Current-state assessment

### Verified repository facts

| Existing property | Reuse unchanged | Exposure implication |
| --- | --- | --- |
| `punarod` is currently a loopback-only alpha relay; the accepted production target is not yet released. | Yes. | No current direct public service is authorized. ([`DESIGN.md`](../DESIGN.md)) |
| `PUNARO_INGRESS_MODE=proxy` or `internet` requires loopback binding and a canonical HTTPS public URL. Trusted-LAN plaintext is an explicit private/link-local CIDR and observed-peer exception. | Yes. | Never carry trusted-LAN HTTP into Tailscale Funnel or Cloudflare. ([`README.md`](../README.md)) |
| Device enrollment is single-use and bound to a client value; a generated 256-bit device secret is stored only as a SHA-256 digest. Sessions/credential caches revalidate within two seconds. | Cryptographic and authorization semantics: yes. Ingress contract: no. | Issuance remains private. Existing bounded redemption remains available only through the Access-protected native ingress (or tailnet), not the MCP hostname. Device credentials remain native-client credentials, not OAuth or Access substitutes. ([`DESIGN.md`](../DESIGN.md)) |
| Legacy relay calls use enrolled Ed25519 machine identity, method/path/body-hash/timestamp/nonce signatures, endpoint-namespace enrollment, idempotency, and server-authorized memberships. | Yes. | Preserve it for relay/device traffic regardless of transport. ([`DESIGN.md`](../DESIGN.md)) |
| Native `punaro-memory` pins an HTTPS origin, loads a protected credential file, validates an owner-only profile, and does not let MCP arguments override origin or credential path. Windows has dedicated ACL/reparse protections. | Yes. | It is the right client boundary once transport is selected. ([`docs/installation.md`](installation.md)) |
| Remote MCP is **not** currently a server. Metadata can be opt-in and token validation can be opt-in, but token validation still mounts neither transport nor tools. | Yes, as a foundation only. | Do not call the existing build Internet-ready. ([`README.md`](../README.md), [`DESIGN.md`](../DESIGN.md)) |
| Remote-MCP foundation requires HTTPS protected-resource metadata, canonical `/mcp` resource, RS256 JWT issuer/JWKS with `kid`, expiry, exact audience, a scope string, and a one-to-one subject-to-enabled-Punaro-principal binding. Project authority remains server-side. | Foundation only; scoped changes are required. | Initial public scope must exclude current default `memory.propose`; static startup-loaded subject bindings must become durable, immediately revocable grants. This is not yet an authorization server or project grant. ([`DESIGN.md`](../DESIGN.md)) |
| Health and readiness are a separate loopback-only listener; health is never mounted on the device listener. PostgreSQL and blobs have no host-published port in the reference Compose bundle. | Yes. | Keep them non-public. ([`README.md`](../README.md), [`docs/production-compose.md`](production-compose.md)) |
| Logs/audits are intended to be structured and body-free; backup/restore uses explicit lifecycle commands and new-target staging, not live overwrite. | Yes. | Carry the redaction and recovery invariant through every ingress component. ([`DESIGN.md`](../DESIGN.md), [`docs/operator-guide.md`](operator-guide.md)) |

### Missing gates that block safe public exposure

1. A mounted, strict Remote MCP HTTP transport and tool dispatcher do not exist.
2. An OAuth 2.1 authorization server, consent/project-selection UI, authorization-code/token/refresh/revocation implementation, client-registration policy, and browser operator-identity contract do not exist. The Punaro-owned-AS baseline uses a dedicated Access-protected human consent application whose validated Access subject maps to a preconfigured Punaro operator; Access authenticates the approver but grants no project authority.
3. The current remote-MCP subject bindings are static startup configuration, and the default challenge includes `memory.propose`. Hosted MCP requires a durable grant/consent store with immediate disable/unlink semantics and a read-only initial default (`memory.search memory.read`) before exposure.
4. A proxy-origin proof is incomplete for the proposed split. The daemon must not accept a forwarded header merely because it exists. A future ingress contract must authenticate each immediate gateway on a distinct local listener/socket or mTLS service identity, strip all client-supplied `Forwarded`, `X-Forwarded-*`, `CF-*`, and Access headers, and bind a route class (`native-access`, `mcp-oauth`, `oauth-protocol`, `human-consent`, or `tailnet-native`) to that authenticated hop. `Host` or a supplied header alone never chooses the route class.
5. A deployed, audited cloudflared/Tailscale service topology, firewall proof, outage drills, and public-runtime release evidence do not exist. The repository’s public relay/operations release gate remains closed.
6. Current installers build from a reviewed source checkout; they are not a signed, checksummed binary distribution or update channel.

## 2. Trust boundaries and data flows

### 2.1 Travelling native CLI: primary Cloudflare Access route

```mermaid
sequenceDiagram
    participant C as Native CLI / adapter<br/>device credential or machine key
    participant E as Cloudflare edge<br/>TLS + Access policy
    participant T as cloudflared<br/>outbound-only Tunnel
    participant G as Native ingress gateway<br/>authenticated upstream
    participant P as Punaro<br/>device/signed request auth
    participant DB as PostgreSQL authority
    C->>E: public HTTPS cli.punaro.example
    E->>E: Access Allow browser session OR<br/>exact Service Auth token
    E->>T: encrypted Cloudflare Tunnel
    T->>G: TLS on private bridge; forwarded headers stripped
    G->>P: mutually authenticated private hop
    P->>P: validate Access assertion, device credential or Ed25519 signature,<br/>nonce and capability
    P->>DB: authoritative authorization / audit
    DB-->>P: allow or closed error
    P-->>C: HTTPS response; no redirect after the Access admission flow
```

`cli.punaro.example` is a distinct Cloudflare Access application, with an Allow policy for interactive owners and an exact Service Auth policy per unattended native machine. Cloudflare documents both user-browser `cloudflared access login` and header-pair service authentication; the origin validates the Access assertion as well as the separate Punaro device/machine identity ([Cloudflare CLI access](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/), [JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)). Access is admission, not a project grant.

### 2.2 Supported Tailscale private-native path

```mermaid
sequenceDiagram
    participant C as Native CLI / adapter<br/>device credential
    participant T as Tailscale node + grants
    participant G as Tailnet ingress gateway<br/>authenticated upstream
    participant P as Punaro<br/>device/signed request auth
    participant DB as PostgreSQL authority
    C->>T: TLS to tailnet-only name<br/>Tailscale node identity
    T->>G: Tailscale Serve terminates tailnet TLS;<br/>private route only
    G->>P: mutually authenticated private hop<br/>client headers stripped
    P->>P: validate device credential or Ed25519 signature, nonce, capability
    P->>DB: authoritative authorization / audit
    DB-->>P: allow or closed error
    P-->>C: HTTPS response; no redirect
```

**Supported alternative:** use Tailscale *Serve* or a future explicit tailnet TLS listener, never Funnel. For the Serve variant, `tailscaled` terminates tailnet TLS and forwards only to the tailnet ingress gateway; that gateway authenticates to Punaro with its distinct mTLS/service identity. Funnel is Internet-public while Serve is tailnet-only; the same port flips public/private according to the last command ([Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel)). A narrow grant permits only managed laptop tags/groups to TCP 443 on `tag:punaro`, optionally with posture requirements. Tag ownership is restricted to the tailnet administrator, and grants are reviewed as additive (matching grants union their capabilities). It carries the same Punaro device/machine authentication and capabilities as the Cloudflare-native route; it never makes a raw LAN HTTP listener available.

### 2.3 Hosted ChatGPT/Claude Remote MCP route

```mermaid
sequenceDiagram
    participant H as ChatGPT / Claude cloud
    participant E as Cloudflare edge<br/>DNS, TLS, WAF/rate limits
    participant C as cloudflared<br/>outbound-only tunnel
    participant G as MCP ingress gateway<br/>private authenticated hop
    participant M as Punaro Remote MCP resource server
    participant A as Punaro OAuth authorization server
    H->>E: public HTTPS mcp.punaro.example/mcp
    E->>C: encrypted Cloudflare Tunnel
    C->>G: TLS on private bridge; public origin has no listener
    G->>M: mTLS/service identity; strips forwarded headers
    M-->>H: 401 Bearer resource_metadata + narrow scope
    H->>A: public HTTPS metadata / authorize / token flow
    A-->>H: audience-bound access token, rotated refresh token
    H->>M: Bearer token over public HTTPS
    M->>M: issuer/JWKS/exp/aud/scope/subject binding/project capability
    M-->>H: bounded MCP response or body-free OAuth/MCP error
```

TLS terminates at the Cloudflare edge for the Internet connection. Tunnel traffic remains encrypted to `cloudflared`; the connector then uses TLS to the private gateway. The gateway-to-Punaro hop is mutually authenticated. No request may reach the resource server merely by reaching loopback or presenting a forged `X-Forwarded-*` field. Cloudflare documents that Tunnel itself leaves the origin seeing the connector rather than the visitor IP ([Tunnel FAQ](https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/)); client IP is not authorization input.

### 2.3a Optional OpenAI Secure MCP Tunnel route

```mermaid
sequenceDiagram
    participant H as ChatGPT / supported OpenAI product
    participant O as OpenAI-hosted tunnel endpoint<br/>organization/workspace association
    participant T as tunnel-client<br/>runtime API key; outbound HTTPS
    participant G as Private MCP gateway<br/>route-specific mTLS identity
    participant M as Punaro Remote MCP resource server
    H->>O: MCP request under OpenAI product/workspace authorization
    T->>O: outbound HTTPS long-poll to api.openai.com:443<br/>or control-plane mTLS endpoint
    O-->>T: queued MCP request
    T->>G: HTTPS/mTLS to exact private MCP URL
    G->>M: authenticated MCP route; headers stripped
    M->>M: OAuth bearer, durable grant, scope and project capability
    M-->>T: bounded response
    T-->>O: outbound HTTPS response post
    O-->>H: MCP result
```

This option does not expose a Punaro MCP listener or Cloudflare MCP hostname to ChatGPT. OpenAI authenticates `tunnel-client` with a runtime API key and controls tunnel visibility through Platform-organization and ChatGPT-workspace associations/RBAC; optional control-plane mTLS is documented. The local target must be the authenticated private MCP gateway, never Punaro’s raw LAN HTTP profile. OAuth discovery can traverse the tunnel, but OpenAI states that the authorization server is **not** automatically tunneled; the browser-facing AS must remain reachable through the separately designed `auth.`/`consent.` flow. The tunneled protected-resource metadata must advertise the same canonical `https://mcp.punaro.example/mcp` resource identifier as the Cloudflare route, and every token must retain that exact audience; the OpenAI-managed tunnel URL is transport addressing, never a second OAuth resource or accepted audience. If the OpenAI product cannot preserve that contract, option E is no-go. This path is not available to Claude.

### 2.4 OAuth lifecycle

```mermaid
sequenceDiagram
    participant H as Hosted MCP client
    participant M as /mcp resource server
    participant A as Authorization server
    participant U as Operator in browser
    participant C as Access-protected consent UI
    H->>M: unauthenticated /mcp
    M-->>H: 401 + resource_metadata URL + minimal required scope
    H->>M: GET protected-resource metadata
    H->>A: GET AS metadata / JWKS
    H->>A: authorization request (resource, PKCE S256, state, nonce where OIDC)
    A->>U: redirect with opaque one-use consent handle
    U->>C: human login at consent.punaro.example
    C->>C: validate Access issuer/audience/signature/time;<br/>map subject to allowlisted Punaro operator
    C->>U: explicit principal and project/capability consent
    C->>A: authenticated server-side approve/deny transaction
    A-->>H: exact registered redirect URI + one-use code + state
    H->>A: token request + PKCE verifier + resource
    A-->>H: short-lived access token; rotated refresh token only if approved
    H->>M: Bearer access token
    M->>M: validate JWT and current binding/capability/revocation
```

The current MCP authorization specification requires protected-resource metadata and requires clients to use it for authorization-server discovery. It calls for authorization-server metadata/OIDC discovery, resource indicators, PKCE, exact redirect validation, and token audience validation; it prohibits token passthrough ([MCP Authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). The diagram shows the Punaro-owned-AS baseline. Access protects only the human consent UI reached in the operator’s browser; it does not protect MCP discovery, `/authorize`, `/token`, `/revoke`, callbacks, or background tool calls. The alternative Access OAuth spike is conditional on real hosted-client interoperability and a non-bypassable Punaro token-exchange, operator-identity, grant, and capability review.

### 2.5 Relay/device and operations traffic

```mermaid
flowchart LR
  D[Enrolled native device] -->|Tailscale or Access-protected CLI hostname| I[Native ingress]
  I -->|authenticated private hop| P[Punaro]
  P -->|device bearer OR Ed25519 signature, replay and capability checks| R[Relay and memory APIs]
  O[Operator admin host] -->|tailnet only| A[admin CLI / local socket]
  H[localhost only] --> L[/healthz and /readyz]
  B[backup / restore role] -->|private credentials, no listener| DB[(PostgreSQL / blobs)]
```

Administrative, enrollment issuance, backup/restore, database, metrics, JWKS-refresh control, and relay-management traffic remain loopback or tailnet-only. Strict single-use enrollment redemption is the one enrollment exception: it may traverse `cli.` after Access admission so a new laptop without a device credential can enroll. It never shares the public MCP hostname.

## 3. Endpoint exposure matrix

Paths are proposed contracts, not implemented routes. “No body logs” means do not record request/response bodies, MCP arguments/results, authorization codes, bearer/refresh tokens, device credentials, signatures, or key material; retain only timestamp, route class, status, principal pseudonym/opaque ID, decision, and bounded latency/size.

| Path / interface | Caller and reachability | Cloudflare Access | Punaro authentication / authority | Scope or capability | Initial limit | Methods | Body logs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mcp.punaro.example/mcp` | ChatGPT/Claude; public HTTPS through Tunnel only | **None**; Cloudflare WAF/rate controls only | RS256 OAuth bearer with `kid`, issuer/JWKS/exp/exact-aud/scope-string validation, current grant, per-tool project capability | initial `memory.search`, `memory.read`; `memory.propose` and other mutations require later separate consent | 30 req/min per subject + provisional 300/min IP edge; bounded JSON-RPC | POST; GET/DELETE only when the selected Streamable HTTP session contract supports them; every unsupported method gets body-free 405 | Never |
| OpenAI-hosted Secure MCP Tunnel endpoint (optional; OpenAI-managed URL/tunnel ID) | ChatGPT/supported OpenAI product; OpenAI-managed reachability | n/a; no Cloudflare path | OpenAI organization/workspace+tunnel permission at hosted endpoint; runtime API key or control-plane mTLS at `tunnel-client`; Punaro OAuth/grant/capability still required at private MCP target; canonical audience remains exactly `https://mcp.punaro.example/mcp`, never the tunnel URL | same initial read-only MCP scopes; no transport-derived project grant | OpenAI control-plane limits plus 30/min Punaro subject | same strict MCP method contract as the canonical resource; unsupported methods get body-free 405 | Never in Punaro/tunnel raw logs; normal OpenAI app-level compliance logging may apply |
| `mcp.punaro.example/.well-known/oauth-protected-resource` and `mcp.punaro.example/.well-known/oauth-protected-resource/mcp` | hosted client; public | None | public metadata only | n/a | provisional 60/min IP; initial `Cache-Control: no-store` | GET | Never |
| `auth.punaro.example/.well-known/oauth-authorization-server` and `auth.punaro.example/.well-known/jwks.json` | hosted client; public | None | public metadata/keys only | n/a | provisional 60/min IP; initial `Cache-Control: no-store` | GET | Never |
| `auth…/authorize` | hosted client’s user agent; public | None on protocol endpoint | create/validate opaque consent transaction; CSRF, exact client/redirect/PKCE/state/resource checks | requested scopes capped by consentable capability | 10 starts/min browser/session | GET | Never log query, code, or form body |
| `consent.punaro.example/oauth/consent` | human operator browser; public through Tunnel | dedicated human Allow policy; no service-token policy | validate Access assertion and allowlisted operator mapping; require installation owner initially or explicit durable delegated grant authority; approve one-use server-side transaction | only projects/capabilities within the approver’s authoritative grant range | 10 starts/min operator | GET, POST | Never log transaction handle, query, or form body |
| `auth…/token` | hosted MCP client; public | None | client registration/CIMD policy, one-use code, PKCE; refresh rotation and family revocation | resource-bound requested scope | 10/min client+subject; provisional 30/min IP | POST | Never |
| `auth…/revoke` | hosted MCP client/account unlink | None | client authentication where applicable; revoke exact token family | n/a | 10/min client | POST | Never |
| `auth…/register` | only if compatibility testing proves DCR is needed | None; disabled initially | strict DCR validation, SSRF-safe metadata retrieval; otherwise 404 | n/a | 2/min IP | POST | Never |
| `cli…/v1/device/session`; `cli…/v1/device/session/revoke` | enrolled interactive/unattended native client; public through Tunnel | interactive human Allow or exact per-machine Service Auth | Access JWT **and** Punaro device credential/session control | own device lifecycle only | 30/min device + edge controls | GET session; POST revoke | Never |
| `cli…/v1/projects/resolve`; `cli…/v1/projects/{project}/memories/{item}`; `…/memories/search`; `…/memories/hybrid-search`; `…/memories/brief`; `…/memories/changes`; `…/memory-proposals/{proposal}` | native memory client; public through Tunnel | same exact `cli.` Access app | Access JWT **and** Punaro device credential; project authorization on every call | existing project read/search capability; hybrid route only when enabled | 60/min device; lower expensive-search quota | POST resolve/search/hybrid/brief/changes; GET memory/proposal | Never |
| `cli…/v1/projects/{project}/memories`; `…/memories/{item}`; `…/memories/{item}/state`; `…/memory-proposals`; `…/memory-proposals/{proposal}/approve`; `…/reject` | authorized native memory writer/operator; public through Tunnel | same exact `cli.` Access app | Access JWT **and** Punaro device credential; mutation/idempotency/ETag and project capability | existing create/update/archive/delete/propose/approve/reject capability, separately authorized | 30/min device; lower mutation quota | POST create/state/propose/approve/reject; PUT update; DELETE purge | Never |
| `cli…/v1/trusted-attachments`; `…/trusted-attachments/{artifact}`; `…/{artifact}/content` | authorized native attachment client; public through Tunnel | same exact `cli.` Access app | Access JWT **and** Punaro device credential; trusted-attachment policy/project authority | existing reserve/upload/download/delete capability | existing size/deadline limits; 30 control calls/min device | POST reserve; PUT content; GET artifact; DELETE artifact | Never |
| `cli…/v1/conversations`; `…/v1/notifications`; `…/v1/machines/me/endpoints`; `…/v1/roles/bindings`; `…/v1/conversations/{conversation}/messages`; `…/invocations`; `…/sender-validation`; `…/controls`; `…/controls/audit`; `…/v1/deliveries/lease`; `…/v1/invocations/lease`; `…/v1/invocations/{invocation}/outcome`; `…/v1/deliveries/{delivery}/ack` | enrolled native relay/agent client; public through Tunnel | same exact `cli.` Access app | Access JWT **and** Ed25519 signed request with body hash/timestamp/nonce; server membership/capability/idempotency | existing conversation, endpoint, role, delivery and invocation grants | 60/min machine plus existing lease/queue limits | GET conversations/notifications; PUT endpoints; POST every other listed route | Never |
| tailnet CLI name (optional) | native client; tailnet-only mirror of the exact device, memory, attachment, relay and redemption rows above | none; narrow tailnet grant is admission | same Punaro device credential or Ed25519 signature and per-route authority as `cli.` | identical application capabilities; no tailnet-derived project grant | same server limits as `cli.` | exactly the methods above; no wildcard pass-through | Never |
| enrollment issuance | owner only; loopback/tailnet administrative interface | n/a | owner-admin/local OS authority | narrowly named enrollment grant | 5/min issuer | local CLI/private POST | Never |
| `cli…/v1/enrollments/redeem` or tailnet equivalent | new native client; Access-protected public native ingress or tailnet | human Access session or exact per-machine Service Auth on `cli.`; tailnet grant on private route | single-use bound redemption; device credential is the output, not an input | exact enrollment grant only | 5/min client plus edge controls | POST only | Never |
| admin, relay management, backup/restore, database, blob, metrics | operator/service only; loopback or tailnet only | n/a | owner DSN/local OS/service identity; never OAuth | admin only | deny public | local CLI/private socket | Never |
| `/healthz`, `/readyz` | local supervisor only; loopback only | n/a | network isolation; no external health proxy | n/a | local | GET | Never; fixed status body contains no inventory |

Use distinct hostnames instead of path exceptions. Cloudflare Access supports path-specific applications, but a bypass disables Access enforcement and logging ([Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)); using it as a public-MCP workaround would be misleading. `mcp.` is intentionally a separate public OAuth-protected resource, not an Access “bypass” of an otherwise protected general hostname.

## 4. Authentication model

| Credential family | Issuance/storage/audience | Lifetime and rotation | Revocation/compromise response | Must not substitute for |
| --- | --- | --- | --- | --- |
| Cloudflare Access user identity | IdP → Access browser session; audience is exactly `cli.` or the separate `consent.` application | Access session policy; Access JWT validated for issuer, audience, signature, time | revoke IdP/Access session; deny at edge and origin; invalidate pending consent transaction | OAuth token, device credential, Punaro operator mapping, project grant |
| Cloudflare Access service token | one exact machine or unattended service; OS keychain/private service credential | finite expiry; overlap new pair before retiring old | delete exact token; invalidate service path | OAuth bearer or Punaro machine key |
| Tailscale node identity | enrolled node and tag-owned identity | tailnet policy/device lifecycle | expire/remove node, revoke tag/grant | application principal/device credential |
| Punaro device credential | owner-authorized, single-use bound enrollment; protected file/keychain | short session, generation/cache recheck ≤2s per current design | disable principal/credential generation; stop native service; re-enroll after loss | Cloudflare and OAuth identity |
| Punaro machine signing key | installer-generated private key, protected OS store; public key in explicit enrollment | rotate with explicit new-machine lifecycle | remove/revoke enrollment and close nonce replay path | bearer credential or OAuth client credential |
| Punaro consent transaction/operator mapping | AS creates an opaque one-use transaction; `consent.` validates an Access subject against a preconfigured operator allowlist; initial issuance authority is installation-owner only, and any later delegate must hold explicit server-side grant authority for the selected project and capability | minutes; one use; server-side only; no authority in browser handle or Access identity | cancel transaction, remove operator mapping/delegation, revoke Access session; audit approve/deny without body | OAuth client identity, hosted end user, project capability |
| MCP OAuth access + refresh tokens | authorization server after user consent; stored by hosted client, never returned to model/prompt | short RS256 access tokens with `kid`, exact MCP audience and scope string; rotated refresh-token family only if host supports it | token-family/subject/client revocation; recheck durable grant/capability per request | Access JWT, service token, device key |
| Project capabilities and OAuth grants | durable database authority from an authenticated operator consent decision | effective immediately; no reliance on bearer expiry or startup-only config | disable subject, revoke grant, unbind project; every invocation rechecks | network or identity admission |

Cloudflare Access validates an edge-issued assertion; Cloudflare recommends validating `Cf-Access-Jwt-Assertion` with the application audience and rotating signing keys rather than trusting a static key ([JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)). For native unattended service-to-service use, Access documents a client-ID/secret header pair and finite token lifecycle ([service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/)). Neither is a project authorization claim.

## 5. Hosted MCP compatibility

### Supported flow to build and validate

1. Publish only `https://mcp.punaro.example/mcp` and `https://auth.punaro.example` through Cloudflare Tunnel; both are public HTTPS endpoints, while their origin has no public listener.
2. On unauthenticated MCP access, return a standards-compliant `401 Bearer` challenge naming protected-resource metadata and only the minimal requested scopes. For the initial pilot that means `memory.search memory.read`, which requires removing `memory.propose` from the current default challenge. Serve metadata and authorization-server metadata/JWKS publicly, TLS-only, body-free, and initially `Cache-Control: no-store` to match the current security-header behavior.
3. Accept authorization code + PKCE S256, `state`, a resource indicator exactly equal to the canonical `/mcp` URL, and `nonce` whenever the selected identity layer is OIDC. Validate canonical issuer, exact redirect URI, client ID and client metadata/DCR policy before creating a code. Code is short lived, one-use, bound to client, redirect, PKCE, resource, subject, and selected project/capability set. The baseline is Punaro’s AS; an Access OAuth spike must terminate in a one-use Punaro exchange that issues the final Punaro token only after the same grant checks. The selected issuer/exchange is explicit and allowlisted by the resource server.
4. For the Punaro-owned AS, `/authorize` creates an opaque one-use transaction and sends the human browser to the dedicated Access-protected `consent.` application. That application validates the Access assertion and maps its issuer+subject to a preconfigured enabled Punaro operator before showing the principal/project/capability chooser. For the initial deployment, only the installation owner may approve; any future delegated approver must have an explicit durable Punaro grant-authority record covering the selected project and every selected capability, checked again at approval time. Its server-side approval binds an existing enabled Punaro principal and records a durable opaque grant. The browser handle, Access identity, operator allowlist membership, token request, MCP parameter, hostname, and forwarded headers never carry project authority. Cloudflare Access OAuth must demonstrate an equivalent reviewed identity-to-grant ceremony and cannot make its admission token authoritative for a project.
5. Issue audience-bound short-lived access tokens. Refresh tokens are optional for the first read-only milestone; when issued, rotate on each use, detect replay, and revoke the whole family. ChatGPT’s current documentation says OAuth/OIDC refresh requires a provider that advertises and issues refresh access (commonly `offline_access`) ([ChatGPT developer mode](https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt-beta)).
6. Disconnect/unlink invokes the provider/client revocation endpoint if supported and must be complemented by a Punaro “connected clients” page that revokes token family, durable subject binding, and selected project consent. The existing startup-loaded `PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON` is insufficient for this contract and must be replaced before exposure. In all cases, server-side disablement wins immediately.

### Client registration and Cloudflare Access decision

The MCP specification says client-ID metadata documents are preferred/recommended, dynamic client registration is optional, and static preregistration is a valid fallback. It requires the server to defend metadata fetching against SSRF and to validate redirect URIs exactly ([MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). **Initial recommendation:** support static preregistration and HTTPS client-ID metadata documents; keep DCR unmounted until ChatGPT and Claude compatibility tests establish it is required and the SSRF design is reviewed. Claude’s setup UI can optionally take an OAuth client ID and secret, which supports a preregistered-client test path ([Claude remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)).

Do not place *browser/session Access or header-pair service auth* in front of `mcp`, protected-resource metadata, authorization-server metadata/JWKS, `authorize`, `token`, `revoke`, or the client callback. The official documents do not establish that hosted MCP clients can satisfy those mechanisms on discovery and background calls. The separate `consent.` Access application is safe to test because only the human operator’s browser visits it and approval returns to the AS over an authenticated server-side channel; failed Access/JWKS/operator mapping cancels the transaction. Cloudflare Access OAuth is the other narrowly scoped exception to evaluate: its metadata, issuer/resource/audience behavior, token format, exchange, scopes, subject binding and revocation must pass both hosted-client tests. A public OAuth-protected resource is not unauthenticated application access: Punaro capabilities remain mandatory and fail closed.

### Exact hosted-client validation gates

Run against disposable principals/project data, with no production bodies:

| Client | Required proof before enablement | Not assumed |
| --- | --- | --- |
| ChatGPT web | Workspace/plan permits developer mode or custom app; scan reaches public metadata; OAuth completes; the human-only `consent.` Access redirect works without gating protocol calls; refresh survives expiration if requested; frozen read-only tools behave; unlink/revocation denies next call. Token must be RS256, carry `kid`, scope string, exact MCP audience, and allowlisted issuer. Repeat with the selected AS. | tailnet access, Access on protocol/background calls, service-token header injection, DCR support, write actions on every plan. |
| Claude web | Custom remote connector accepts public URL; OAuth redirect/token exchange and human-only consent work; access is from Anthropic cloud; read-only tool call and disconnect/revocation work. Token must meet the same format/claim contract. Repeat with the selected AS. | tailnet access, local Desktop network path, Access/service-token headers on protocol calls, DCR support. |

The current official ChatGPT and Claude setup pages do not publish stable OAuth callback URLs. Do not guess or wildcard them. At each disposable hosted-client validation, capture the exact redirect URI supplied by the product UI, client metadata document, or authorization request; preregister that exact HTTPS value and retain it as dated evidence. If the product supplies no stable exact value and cannot complete a reviewed DCR/client-metadata flow, that client is **no-go**. OpenAI Secure MCP Tunnel does not remove this requirement because its documentation says the authorization server is not automatically tunneled.

Hosted-client failures must be generic: stable 401 `invalid_token`, 403 `insufficient_scope`/forbidden, 429, or opaque 5xx; do not echo token fragments, authorization codes, project existence, MCP arguments/results, upstream diagnostics, or retry topology.

## 6. CLI access

| Option | Result | Recommendation |
| --- | --- | --- |
| `cloudflared access login` | Interactive browser login obtains an Access session token; Cloudflare documents this for user CLI use, not a service integration ([CLI guide](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/)). | **Primary interactive laptop flow**, still requiring Punaro device/signed auth. |
| Access service token | Unattended header-pair admission for one exact Access application. | **Primary unattended native flow**; one pair per machine/service, stored in OS service credential/keychain. |
| Direct tailnet HTTPS / Tailscale Serve | Private reachability, tailnet ACL/grant and node identity; no public DNS listener. Current loopback-only daemon needs a future authenticated tailnet ingress implementation. | Supported alternative native path for a peer-operated tailnet; never a required hosted-client dependency. |
| Punaro device credential over either selected transport | End-to-end application principal and project/capability enforcement. | **Always required** for device API; no transport credential replaces it. |

macOS: keep device secret/key material in Keychain or protected installer state; use launchd for adapters. Linux: user/system service credentials with strict ownership and no token in environment/argv. Windows: current-user protected ACL/DPAPI-compatible installer state and scheduled task; reject reparse points. Enrollment is operator-authorized and single use, then disabled clients remain disabled until owner registration and explicit enablement. Lost device: remove its Tailscale node/tag grant, revoke Access service token if present, disable the Punaro device/machine enrollment and project memberships, and issue a new credential—never “restore” the old secret.

Enrollment issuance is always an owner action over loopback or tailnet administration. For a new interactive laptop, the owner transfers the short-lived enrollment material out of band, the laptop completes `cloudflared access login`, and only then calls the bounded redemption path on `cli.`; an unattended machine must first receive its exact Access service token through the operator’s secret channel. A tailnet peer may redeem over its granted private route. Redemption never accepts ambient proxies or redirects, never exposes issuance, and yields only the enrolled Punaro credential bound by the existing protocol.

## 7. Threat model and verification

| Threat | Enforcing component | Concrete acceptance test |
| --- | --- | --- |
| Tunnel/origin bypass | no host-published port; firewall; private bridge; mTLS ingress identity | from Internet/LAN and host external IP, TCP 80/443 is refused; only hostname through Tunnel reaches gateway. Cloudflare provides this exact origin-lockdown test pattern ([Tunnel FAQ](https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/)). |
| Stolen device, OAuth, or Access credential | separate audiences; short expiry; server revalidation; immediate revocation | revoke each family independently; verify it fails while other legitimate family still works only where required. |
| Bearer replay | audience/resource validation, short access lifetime, refresh rotation/replay family revoke | replay access at wrong host/resource; replay rotated refresh token; both fail and family is revoked. |
| Compromised tailnet node | deny-by-default grants, exact tags/ports/posture, Punaro auth | use non-granted tailnet node and a granted-but-revoked device; both denied. |
| Malicious redirect/OAuth mix-up | exact registered URI/client/issuer/resource/state/PKCE/nonce | altered redirect, issuer, state, code verifier, and resource all fail before token issuance. |
| DNS rebinding / SSRF | canonical HTTPS allowlists, no arbitrary fetch; DCR/CIMD SSRF control | private-IP, redirect, DNS-rebinding and oversized client-metadata URLs rejected with no outbound private request. |
| Spoofed forwarding/CF headers | gateway strips all incoming headers; authenticated gateway-to-Punaro hop | send forged `CF-*`, `Forwarded`, and `X-Forwarded-*` from each edge path; no identity/secure-origin state changes. |
| OAuth consent impersonation/phishing | dedicated Access audience, operator allowlist, opaque one-use transaction, exact callback/state, server-side approval channel | non-allowlisted Access subject, replayed/expired handle, wrong Access audience, and altered callback all fail without creating a grant. |
| Excessive MCP permission or consent over-grant | initial `memory.search memory.read` challenge; owner-only initial consent; explicit delegated grant authority; OAuth scopes plus per-tool project capabilities | default challenge omits `memory.propose`; a `memory.search` token cannot read/write another project or invoke proposal/mutation tools; an allowlisted but non-owner/under-privileged operator cannot grant a project or capability outside its durable grant-authority record. |
| Secret/body logs | typed redaction schema; proxy/app log config; release probe | inject unique canary in body, token, code, signature; scan edge/gateway/app/audit logs and backup metadata for absence. |
| DoS/expensive query | Cloudflare WAF/rate, gateway limits, bounded JSON/queues/deadlines, per-subject quota | burst metadata/token/MCP malformed and expensive calls; prove 429/backpressure and normal traffic stays within SLO. Treat IP-edge limits as provisional because hosted vendors may share egress IPs: validate them during both vendor pilots, adjust with recorded evidence, and never weaken per-subject/client quotas or create an unauthenticated bypass. |
| Cloudflare/Tailscale outage | independent transports; readiness and explicit degraded state | disable tunnel or tailnet; public MCP fails closed; private CLI alternate only if explicitly configured; no LAN fallback. |
| Stolen OpenAI tunnel credential or wrong workspace association | runtime API key/control-plane mTLS, Platform tunnel RBAC, exact organization/workspace associations, Punaro OAuth | use wrong workspace/organization, revoke runtime key, remove association, and replay old key; tunnel becomes undiscoverable/unusable and Punaro still denies calls without a valid grant. |
| Health/admin/database exposure | separate loopback listener, no published DB/blob ports, tailnet-only admin | external route scan matches the exact endpoint matrix, including both PRM aliases and Access-protected `cli.`/`consent.`; health/admin/5432/blob and every unlisted path fail. |

## 8. Deployment and operations

### Recommended topology

- One Linux host/LXC: PostgreSQL and blobs remain loopback-only under the current host-networked reference bundle. A future private bridge is acceptable only after review; until then host firewall and exact loopback binds are the isolation boundary. `punarod` is non-root and health has a distinct loopback listener.
- `cloudflared` has a dedicated service identity and only outbound Internet access. It points `cli.`, `mcp.`, `auth.`, and `consent.` to exact allowlisted ingress routes, never directly to database, health, admin, or LAN HTTP. `cli.` and `consent.` have separate Access applications/audiences; `mcp.` and OAuth protocol endpoints do not.
- The supported tailnet ingress has a different service identity and private bridge/mTLS credential; its Tailscale grant admits only chosen client tags/groups to HTTPS. It is deployed only for peers who choose the tailnet path. Disable Funnel explicitly in tailnet policy and deployment checks.
- If option E is enabled, `tunnel-client` is a separate non-root service with an exact OpenAI tunnel ID, least-privilege runtime API key (or control-plane mTLS), explicit organization/workspace associations, and only outbound access to the documented OpenAI control-plane host plus the local authenticated MCP gateway. Its `/healthz`, `/readyz`, `/metrics`, and `/ui` remain loopback-only; raw HTTP logging stays disabled. Removing the association/key and stopping this service is the emergency shutdown.
- Ingress is split into distinct authenticated local backends: native-Access, MCP resource, OAuth protocol, human consent, and optional tailnet-native. Each gateway/backend pair enforces its host/path/method/size/time contract, strips inbound identity/forwarding headers, and authenticates to Punaro or the AS via a route-specific socket or mTLS service identity. Future code rejects direct traffic or a mismatched route class even when `Host` and forwarded headers look valid.
- TLS/DNS: Cloudflare owns public `mcp.`/`auth.` DNS and edge certificates; Tailscale owns tailnet HTTPS naming/certificates; do not mix trust roots. Public URL and OAuth issuer/resource are canonical immutable configuration values.

Store tunnel token, database DSNs, gateway mTLS keys, OAuth signing/rotation keys, and Access service pairs only in root/OS secret facilities or a secret manager, mounted read-only to the one service that needs each. Never place them in generated docs, fixtures, `.env`, command line, container image, browser URL, audit event, or test report. Keep signing-key use in a dedicated authorization-server identity separate from Punaro database ownership.

Start order: database/bootstrap and schema compatibility → protected config/secrets and durable grant-store validation → OAuth key/JWKS/operator-mapping readiness → authenticated route-specific ingress gateways → Punaro resource server → cloudflared/Tailscale publication. `/readyz` is healthy only when database, current grant/revocation state, required JWKS/config freshness, ingress proof, and enabled components are valid; it must not make a public route. A failed Cloudflare Access/JWKS/OAuth-policy validation prevents readiness and accepts no protected request.

Monitoring exposes counters/latency/status only: tunnel connected, gateway TLS/mTLS failures, Access validation failures, OAuth issue/refresh/revoke outcomes, token audience/scope/capability denials, rate-limit events, queue/DB deadlines, backup age/verification, and credential expiry lead time. Edge dashboards must distinguish provisional shared-IP throttles from per-subject/client quotas; milestones 4–5 record vendor egress observations and the evidence for any IP-budget adjustment without weakening authenticated quotas. No request/response content, principals’ names, bearer material, or URLs with query values.

Back up encrypted database exports, blob metadata/content per current backup contract, and non-secret configuration/version manifests. Test restore into a new isolated target; restore must invalidate/reconcile active session material, preserve revocation records, and never overwrite a running stack. Rollback is tunnel route withdrawal/disable first, then application release rollback only with the existing backup/update journal. Emergency public shutdown: disable or stop the specific `cloudflared` tunnel route and revoke its token; leave tailnet-only operator access available. Prove no origin bypass with external and LAN port scans plus direct-IP HTTP(S) failure, while the named Tunnel route succeeds.

## 9. Release and distribution implications

For an initial *private, tailnet-only* native deployment, a pinned, reviewed source checkout can be acceptable if the exact commit, local build commands, binary hashes, installer output, OS, and manual update/revocation procedure are retained as deployment evidence. It is not a public client-distribution mechanism. The current installers build from the checkout; they do not establish publisher identity, signed release artifacts, transparent checksums, secure auto-update, rollback channel, or advisory process ([`docs/installation.md`](installation.md)).

Internet exposure must wait for the remote-MCP/runtime/release gates above, but it must **not** be conflated with later signed-artifact distribution. A later milestone must provide platform-native signed binaries/installers, SHA-256 checksums and provenance/SBOM, a documented stable/beta update channel, key rotation/revocation guidance, rollback behavior, and end-to-end update verification for macOS, Linux, and Windows.

## 10. Phased delivery plan

| Milestone | Deliverable and acceptance tests | Rollback | Explicitly not exposed |
| --- | --- | --- | --- |
| 0. Architecture contract | approve this document; threat table, endpoint matrix, ingress-proof contract, source citations reviewed | no runtime change | everything |
| 1. Authenticated ingress and origin hardening | build route-specific gateway identities locally; Tunnel has no inbound host port; prove route allowlist, mTLS/socket identity, direct-IP denial, forged-header rejection, body-free unsupported-method 405, and emergency withdrawal before publishing any hostname | stop gateways and retain the original loopback service | every public hostname; raw LAN HTTP; Funnel |
| 2. Cloudflare Access native bootstrap and Tailscale alternative | publish only `cli.` enrollment redemption and device session/revocation after milestone 1; exact Access policies; issuance stays private; interactive/unattended redemption, device, revocation, and lost-device tests on macOS/Linux/Windows; optional Serve grants deny non-member/non-443 | disable `cli.` route/policy and/or Serve grant; retain loopback | memory, attachment, relay, MCP/OAuth, health/admin/DB, Funnel |
| 2a. Native application-route expansion | qualify each `cli.` memory and attachment row independently with route/method/size/auth/capability/redaction tests; expose legacy relay rows only after every applicable **Public relay and operations (closed)** prerequisite in [`docs/security-release-gates.md`](security-release-gates.md) is satisfied and recorded against the release candidate | withdraw the affected route family without changing bootstrap routes | every unqualified native family; MCP/OAuth; health/admin/DB |
| 3. OAuth-compatible Remote MCP | strict transport including explicit unsupported-method 405 tests; exact PRM aliases/AS metadata/JWKS; Punaro-owned-AS owner-only initial consent and negative delegated-over-grant tests via `consent.`; durable grants replacing static bindings; default scope drops `memory.propose`; RS256/`kid`/scope-string/exact-aud/issuer tests; run and extend `make remote-mcp-e2e`; optionally test Access OAuth only with a written non-bypassable Punaro exchange/grant contract | withdraw `mcp.`/`auth.`/`consent.` routes, revoke issuer keys and pending transactions | native admin/enrollment issuance/health/DB, `memory.propose` and mutations |
| 3a. OpenAI Secure MCP Tunnel spike (optional) | verify plan/RBAC, tunnel ID/workspace association, official signed/checksummed `tunnel-client`, outbound-only network, local mTLS MCP target, OAuth discovery/consent, revocation, log boundary, equivalence with the Cloudflare MCP route, and rejection of the tunnel URL or any other wrong resource/audience | remove association/key; stop `tunnel-client`; no fallback unless explicitly configured | Claude and any automatic public-route fallback |
| 4. ChatGPT validation | workspace approval, capture/register exact callback, compare public Cloudflare route with option E, exact OAuth discovery/login/consent/refresh/unlink; read-only tool scan; negative wrong-format/issuer/aud/scope/operator tests; record shared-egress behavior and tune only provisional IP budgets without weakening subject/client quotas | disable app and selected tunnel/public route | Claude, proposals, and writes |
| 5. Claude validation | public-cloud reachability, OAuth/connector/add/remove, human consent, read-only tool and immediate revocation tests; record shared-egress behavior and tune only provisional IP budgets without weakening subject/client quotas | remove connector and public route | ChatGPT changes, proposals, and writes |
| 6. Revocation/incident exercises | stolen credential, token replay, tunnel emergency shutdown, outage, restore, log-canary, origin scan drills with evidence | documented recovery runbook | broad client distribution |
| 7. Signed distribution | signed/checksummed installers, channel/rollback/update docs and platform verification | pin previous signed release | no automatic expansion of public tools |

Each milestone requires independent security review and committed release evidence. Later milestones cannot bypass prior negative tests merely because a hosted connector reaches the endpoint.

## 11. Final recommendation and go/no-go

**Recommend option C, Cloudflare-first hybrid, with option D only as a constrained admission/exchange trial and option E as an optional ChatGPT hardening profile.** Cloudflare Tunnel + Access is the primary access route for own laptops and native unattended clients at `cli.`. Cloudflare Tunnel is also the only public origin path for the small Remote MCP/OAuth hostnames. Browser/session Access or exact service-token Access applies to `cli.`; it is not placed in front of hosted MCP/OAuth protocol endpoints. Tailscale is a supported peer-selected private-native alternative, not a dependency and never a hosted-client path. For hosted MCP, start with the Punaro-owned standards-based AS. Cloudflare Access OAuth is adopted only if the two vendor validations and a non-bypassable Punaro exchange/grant contract pass. Punaro JWT validation, durable subject binding, and per-project capabilities remain authoritative.

Option A fails if it means browser/session Access or service-token headers on every path; current primary documentation does not establish that hosted connectors can supply those. Option B cannot serve Claude’s hosted connector. **Option D is not automatically simpler: Cloudflare Access OAuth is standards-based admission, but Punaro still needs project consent and a compatible final token. Option E is now officially viable for private ChatGPT developer-mode use and should be piloted as a hardening profile; it does not replace the Claude Cloudflare route and therefore is not the simpler two-vendor default.** Tailscale Funnel is separately rejected because it creates a public service and would violate the no-raw-LAN/no-public-listener posture; a simpler public reverse proxy without Tunnel loses the desired outbound-only origin posture.

**Tailnet- or loopback-only:** native admin, enrollment issuance, relay management, backup/restore, database/blob, metrics, and health; Tailscale is a supported peer-selected private-native transport.

**Publicly reachable through Cloudflare Tunnel:** the exact native `cli.` matrix, consent UI, `/mcp`, both protected-resource metadata aliases, authorization-server metadata/JWKS, and the minimal OAuth authorization/token/revocation endpoints; DCR only after proof of need and SSRF review. Under option E, ChatGPT uses an OpenAI-hosted tunnel endpoint instead of the Cloudflare `/mcp` route, but Claude still uses the latter.

**Access-protected:** `cli.` for primary native access and a separately-audienced `consent.` human operator UI for the Punaro-owned AS; never browser/session or service-token Access on `mcp.` or OAuth protocol/background endpoints.

**MCP OAuth-protected:** all hosted MCP requests, with OAuth discovery remaining publicly reachable as required by the MCP specification.

Go only when all are true:

- [ ] A reviewed implementation provides mounted Remote MCP transport, OAuth server, exact ingress-origin proof, and all negative tests.
- [ ] The browser operator identity is explicit: Access issuer+subject maps to an allowlisted Punaro operator only on `consent.`, or the selected AS provides an independently reviewed equivalent; no network identity grants a project.
- [ ] ChatGPT and Claude have each passed their separate disposable end-to-end flow; neither requires tailnet membership, `cloudflared`, arbitrary Access headers, or an Access browser session.
- [ ] Public origin scans prove no direct listener; only the endpoint matrix paths are externally reachable.
- [ ] OAuth/JWKS/Access policy failures fail closed; no redirects occur on signed/device flows.
- [ ] Durable per-project consent/capability and revocation replace startup-only subject bindings and take effect immediately; initial challenge omits `memory.propose`; wrong token format, issuer, audience, scope and replay are denied.
- [ ] Full logging-redaction, rate/abuse, outage, backup/restore, and emergency-tunnel-shutdown drills have reviewable evidence.
- [ ] The relevant Punaro release gates, protected review, and operations approval are complete.

## Sources

### Primary external documentation

- Cloudflare: [Tunnel](https://developers.cloudflare.com/tunnel/), [Tunnel origin isolation FAQ](https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/), [Access JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [service tokens](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/), [Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/), [CLI Access flow](https://developers.cloudflare.com/cloudflare-one/tutorials/cli/), [Access OAuth for coding agents](https://developers.cloudflare.com/cloudflare-one/access-controls/authenticate-agents/).
- Tailscale: [grants syntax](https://tailscale.com/docs/reference/syntax/grants), [Funnel and Serve distinction](https://tailscale.com/docs/features/tailscale-funnel).
- OpenAI: [ChatGPT developer mode and MCP apps](https://help.openai.com/en/articles/12584461-developer-mode-and-full-mcp-connectors-in-chatgpt-beta).
- OpenAI: [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
- Anthropic: [Claude custom remote MCP connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).
- MCP: [Authorization specification, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

### Repository evidence

[`DESIGN.md`](../DESIGN.md), [`README.md`](../README.md), [`docs/installation.md`](installation.md), [`docs/operator-guide.md`](operator-guide.md), [`docs/production-compose.md`](production-compose.md), [`docs/remote-mcp-e2e.md`](remote-mcp-e2e.md), and [`docs/security-release-gates.md`](security-release-gates.md). The worktree base was `9d3c54f`; implementation review must record fresh `git rev-parse HEAD` output and recheck these exact paths rather than relying on this historical pin.
