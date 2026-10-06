# Architecture and decisions

```text
trusted local YAML       Trivy executable/cache       external JSON/feed files
       |                          |                            |
    Settings                 scanner                      adapters/feeds
       |                          |                            |
       +----------------------- Run/Finding -------------------+
                                  |
                          SQLite immutable snapshots
                                  |
              +-------------------+--------------------+
           comparisons         reports            response plans
                                  |
                        CLI / local API / Textual
                                  |
                        same-origin local dashboard
```

This is a manually verified module/data-flow sketch, not a Graphify execution.

1. Use a mature scanner for vulnerability matching. Writing a new advisory matcher
   would increase maintenance and false-positive risk. Trivy executes; Grype is an
   import adapter only. No claim of better detection than either upstream engine.
2. Persist source assertions, backend version, local target identity, coverage, dates,
   and enrichment provenance. Package identity includes ecosystem/vendor/location
   and version. Backend context is not collapsed into name-only matching.
3. Treat disappearance as "no longer observed" only for complete, comparable runs.
   Missing target identity, changed backend/coverage/version/mode, or partial results
   keep absent observations unresolved. A hash binds a path, not file contents or a
   machine identity; imports alone are insufficient proof of the same subject.
4. Keep the service local-only and single-process. Configured target names are the
   only scan inputs accepted over HTTP. No upload/path/command APIs. Tokens belong
   in a hidden prompt or private process environment, never browser storage or URLs.
5. Make response plans descriptive. Explicit artifact holding is separate from scans,
   needs exact digest confirmation, and is not containment. No package manager runs.

API list views use bounded summaries instead of hydrating all findings. Individual
snapshots are bounded by configured finding/report limits; SQLite files can still
grow indefinitely. Back up and retain/delete data according to your needs.
