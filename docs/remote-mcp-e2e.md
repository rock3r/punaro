# Remote MCP release-candidate E2E evidence

The remote MCP release candidate is qualified with a black-box test against a
disposable deployed endpoint. The test does not provision an endpoint, mint
tokens, or infer deployment topology. An operator supplies a private test
configuration after deploying the exact candidate commit.

Run the test from the candidate checkout:

```sh
PUNARO_REMOTE_MCP_E2E_CONFIG=/private/punaro/remote-mcp-e2e.json make remote-mcp-e2e
```

The target fails when the configuration variable is unset. The tagged Go test
skips unless the target explicitly enables it, so ordinary developer and CI
test runs execute the offline TLS harness but cannot touch a remote deployment.

Keep the configuration outside the repository, readable only by the release
operator, and never attach it to CI logs or the release record. Its shape is:

```json
{
  "candidate_commit": "0123456789abcdef0123456789abcdef01234567",
  "endpoint": "https://candidate.example.invalid/mcp",
  "resource": "https://candidate.example.invalid/mcp",
  "authorization_server": "https://issuer.example.invalid",
  "protocol_version": "2024-11-05",
  "tokens": {
    "valid": "private-token-for-the-authorized-read-only-tool",
    "invalid": "private-malformed-or-unrecognized-token",
    "wrong_issuer": "private-token-from-a-different-issuer",
    "wrong_audience": "private-token-for-a-different-resource",
    "expired": "private-expired-token",
    "revoked": {
      "token": "private-token-or-subject-revoked-before-the-test",
      "expected_status": 403
    },
    "no_scope": "private-valid-token-with-no-required-scope",
    "insufficient_scope": "private-valid-token-that-cannot-invoke-the-forbidden-tool"
  },
  "authorized_tool": {
    "name": "candidate_read_only_tool",
    "arguments": {"query": "release-candidate-e2e"},
    "expected_result": {
      "content": [{"type": "text", "text": "release-candidate-e2e"}]
    }
  },
  "forbidden_tool": {
    "name": "candidate_out_of_scope_tool",
    "arguments": {},
    "expected_status": 403
  },
  "redaction_probe": "remote-mcp-e2e-redaction-probe"
}
```

`candidate_commit` must be the deployed 40-character lowercase Git commit.
`endpoint` and `resource` must be the same canonical HTTPS MCP resource;
`authorization_server` is the canonical HTTPS issuer. The tool arguments must
be JSON objects with no duplicate keys. `protocol_version` must be the supported
MCP version `2024-11-05`, which the disposable client negotiates with the
candidate. Every token and the redaction probe
must be a distinct, at-least-16-character OAuth bearer value made only of
letters, digits, `-._~+/=`. Values above are placeholders, not usable
credentials. `authorized_tool.expected_result` must be the exact non-error MCP
tool result for the disposable probe. It must contain at least one non-empty
text content item; the harness validates it and the request ID exactly.

Prepare a token suite that proves each distinct failure boundary. `valid` must
invoke the configured read-only `authorized_tool` but be denied the
`forbidden_tool`. `no_scope` must be a valid token without any required MCP
default scope. `insufficient_scope` must invoke `authorized_tool` successfully
but lack the operation-specific scope for `forbidden_tool`, which must return
`403` for both scoped credentials.
`wrong_issuer`, `wrong_audience`, `expired`, and `revoked` must each fail for
that stated reason at the candidate boundary, not merely be arbitrary malformed
strings. Set `revoked.expected_status` to `401` for a revoked token (which must
return `invalid_token`) or `403` for a token whose bound subject was disabled
or unbound (which must have no authentication challenge). Use disposable
principals, resources, and data; no test request should name a production
project or contain user content.

The test proves all of the following against the candidate:

- OAuth protected-resource discovery and the unauthenticated challenge;
- malformed, wrong-issuer, wrong-audience, and expired bearers fail with `401`
  and an `invalid_token` challenge; a revoked token fails the configured `401`
  token-revocation or `403` disabled-subject boundary;
- missing required scope and tool-specific insufficient scope fail closed;
- the MCP `initialize` / `notifications/initialized` lifecycle negotiates the
  configured protocol before any tool invocation;
- duplicate-member JSON-RPC input fails without executing a request;
- a valid scoped bearer reaches its configured tool; and
- failure headers and bodies do not echo any supplied token or the redaction
  probe.

The test logs only the candidate commit on success and intentionally withholds
the endpoint, tokens, request bodies, response bodies, and topology on failure.
Its own TLS-backed fixture validates the complete harness flow locally; the
release command remains the authoritative deployed-candidate check.
`candidate_commit` must match `git rev-parse HEAD` in the checkout that runs
the command, and that checkout must have no changes (including untracked or
ignored files), so release evidence cannot be attributed to another build or a
modified test harness.
Record its CI job URL, exact command result, candidate commit, deployment image
digest, approvers, residual risk, and rollback reference in the final
release-evidence record under `docs/release-evidence/` only after the release
process has the required protected-branch and environment approvals.
