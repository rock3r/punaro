# Release evidence records

Every released capability receives its own reviewable Markdown record in this
directory.  Do not use a template, branch name, or mutable URL as evidence.
The record is committed after the candidate commit and CI artifacts exist, and
is reviewed in a final release-only change.  Its authority depends on the
protected-branch, required-CI, signed-tag, and release-environment approval
process described in the security release gates; a Git Markdown file alone is
not immutable evidence.

Required fields:

- release capability and explicit decision (`approved` or `withheld`);
- exact source commit SHA and signed/tagged release reference;
- target OS/architecture and image digest or binary checksum;
- exact commands, results, CI run URLs, SBOM, scan/attestation URLs, and drill
  evidence relevant to the capability;
- named security, cryptography (when applicable), and operations approvers;
- residual risk and expiry/rollback plan; and
- links to each checked gate in `../security-release-gates.md`.

A record may mark a gate checked only when every listed field is present.  An
unchecked gate remains unavailable even if a source branch contains partial
implementation.
