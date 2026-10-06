# Source notes

VulnTrail assembles public-use evidence workflows; it does not publish a novel
advisory database or exploit prediction model.

- [Trivy vulnerability matching](https://trivy.dev/docs/latest/scanner/vulnerability/)
  documents backend matching and ecosystem context. Engine results remain assertions,
  not independently confirmed exploitability.
- [Trivy filesystem flags](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/)
  document the selected offline/update controls. Flags are not OS network isolation.
- [NIST SP 800-40 Rev. 4](https://csrc.nist.gov/pubs/sp/800/40/r4/final)
  informs the identify/prioritize/install/verify lifecycle. VulnTrail intentionally
  leaves installation to the authorized user and supports subsequent verification.
- [CISA KEV data](https://github.com/cisagov/kev-data)
  supplies known exploited vulnerability context through explicitly imported local data.
- [FIRST EPSS](https://www.first.org/epss/) models population-level exploitation
  probability for the next 30 days. It is not a per-device security verdict.
- [uv lock and sync](https://docs.astral.sh/uv/concepts/projects/sync/)
  documents the repository lockfile and locked install workflow.

Feed source dates and SHA-256 hashes are retained. Source validity, licenses, and
freshness remain the operator's responsibility. Offline copies need an intentional
refresh plan; recent import time never replaces source date.
