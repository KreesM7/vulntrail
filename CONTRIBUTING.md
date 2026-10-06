# Contributing

Start with a small issue describing the user problem and evidence. Reproduce bugs
with sanitized synthetic reports, not real private scan output. New ecosystems
must preserve backend/vendor identity, incomplete coverage, and freshness semantics.

Use Python 3.11+, `uv sync --locked --extra dev`, then run the test suite and ruff
checks in README. Add a failing regression test before fixing behavior. Keep the
API loopback-only and data-only configuration; do not add privileged remediation,
shell commands, or automatic downloads as incidental changes.

Pull requests should state what changed, tests run, platform limits, and security
impact. Dependencies and Actions pins require provenance review. Update public
documentation when a contract changes. Respect contributors and report security
issues through SECURITY.md. Contributions use the repository MIT license.

Good first issues: add sanitized Grype version fixtures, improve keyboard navigation
with real browser evidence, or add native Linux/macOS integration coverage.
