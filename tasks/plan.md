# Implementation plan

User directs completion and enhancement within the approved selected-scanner scope and authorizes publishing two public repositories. Preserve Driftline. No remote mutations until tests and sensitive-file review.

Thin slices: validated models/config → real report import and history/export → bounded Trivy execution/watch → local API/dashboard/TUI → feed context and reversible scoped responses → packaging/runtime/security checks → public repositories.

Main owns models/config/adapters/scanner/triage; independent storage/report/response and interface slices may be parallelized only against docs/CONTRACTS.md. No concurrent Git changes. Verification per slice uses python -m unittest discover -s tests -v; packaging uses python -m build; lint uses python -m ruff check . and format --check; audit uses pip-audit on the generated lockfile.

Risks: backend schema variance (strict schema + honest partial state), offline misunderstanding (documentation + missing-cache failure + real engine test), subprocess hangs (timeout/output caps), evidence false resolution (coverage comparison), local API attacks (host/origin/auth/size bounds), dangerous response (digest-bound CLI-only project scope), sensitive repository contents (allowlisted staged paths, no live scan reports).

Public-use quality is not an independently audited production assurance. Native OS/engine/container checks not runnable here remain explicitly recorded; configured CI must actually run after publication before claims of cross-platform certification.
