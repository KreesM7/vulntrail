# Verification evidence — 2026-10-06

## Observed locally

- Windows AMD64, Python 3.12.14: 76 unit/integration/headless tests pass, covering
  models, configuration, adapters, store, reports, feeds, response, scanner, history,
  API, CLI, and Textual UI. Windows loopback/file-handle tests required normal host
  execution because the development sandbox blocked socketpair/rename operations.
- Ruff's configured checks and Git whitespace check pass. No known dependency
  vulnerabilities were reported by pip-audit against the installed locked environment
  on this date. Advisory absence is not supply-chain or code safety proof.
- Trivy 0.75.0 official Windows archive SHA-256 matched official checksums:
  `4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f`.
  This is checksum verification, not Sigstore/signature verification.
- A real database was intentionally provisioned online before scanning. Two genuine
  offline scans of a test requirements file declaring Django 2.2.0 and Jinja2 2.10.1
  each returned 48 backend-reported findings, `pip:requirements.txt` coverage, and
  cached database date `2026-10-06T13:07:05.606377+00:00`. Dependencies were neither
  installed nor executed. Matching subject/coverage scans were comparable.
- Real foreground watch ran twice, persisted two runs, and exited successfully.
  Real JSON/Markdown/HTML exports were generated. Doctor confirmed engine/cache/target.
- Browser runtime: authenticated history, real findings, search, severity empty state,
  detail dialog, comparable history, configured real scan, and sign-out worked.
  HTML export reported download initiation; this browser's download event did not
  expose a saved file, so disk-download verification is not claimed. API report
  responses and independently generated disk exports are tested separately.
- Default desktop and requested 390-pixel mobile viewport rendered without page
  overflow (mobile client/content width 375 pixels after scrollbar). Browser error
  and warning logs were empty. No WCAG certification or screen-reader audit claimed.
- Source distribution and universal wheel built successfully. Repository dependencies
  use generated `uv.lock`; package installers outside the locked workflow may resolve
  different versions.
- A clean wheel-only installation with hash-checked locked runtime dependencies
  exposed the expected CLI commands. No editable source package was used in this check.

## Review corrections

A separate reviewer identified false vulnerability coverage from non-vulnerability
Trivy classes and false disappearance when a target alias was reused. Regression
tests now guard both. Review also prompted resolved network-target rejection and
explicit Windows DACL/shared-writer limits for artifact holding. This was focused
engineering review, not a comprehensive external audit or penetration test.

Initial remote CI rejected a YAML command containing an unquoted trailing colon.
The command is now quoted and a distribution regression test parses workflow YAML.

Windows hosted CI rejected default fixture ownership. The test process temporarily
creates fixtures with its account as default owner, then restores the original
setting. Production ownership checks remain unchanged. This follows
[Microsoft's TokenOwner contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner).

## Limits and pending evidence

Local backend testing was Windows filesystem scanning only. Native Linux/macOS
whole-host coverage, air-gap packet-level enforcement, Java database behavior,
Docker runtime, signed release artifacts, production users, and operational false-
positive/false-negative rates were not established. CI runs fixture/real-process
tests across supported Python/OS combinations; it is not whole-host certification.
Read actual GitHub run results before describing configured jobs as successful.
