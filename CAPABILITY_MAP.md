# VulnTrail capability map

The user approved completing the selected scanner and publishing both projects on 2026-10-06. Implementation decisions are delegated within this scope; destructive responses remain individually approved at runtime.

| Module id | Responsibility | Depends on |
|---|---|---|
| config-policy | Authorized local targets, limits, offline settings | — |
| evidence-store | Immutable scan records, provenance, local persistence | config-policy |
| scanner-adapters | Trivy execution; Trivy and Grype report import | config-policy, evidence-store |
| triage-history | Explicit priority and comparable-run differences | evidence-store |
| scan-orchestrator | Opt-in recurring scans, failures and cancellation | scanner-adapters, triage-history |
| report-export | JSON, Markdown and escaped HTML | triage-history |
| local-api | Authenticated local control and read API | scan-orchestrator, report-export |
| user-interfaces | CLI, Textual TUI and local web dashboard | local-api |
| response-playbooks | Upgrade recommendations; individually approved reversible project-artifact hold | scan-orchestrator |
| distribution | Packaging, Docker, CI, documentation | user-interfaces, response-playbooks |

Build order follows dependencies. API/UI boundaries are documented before parallel implementation. No unrestricted LLM agent, remote network scanner, automatic patching, universal Windows application audit or kernel sensor is in scope.
