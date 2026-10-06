# Security policy

VulnTrail 0.1.x is an early public release. It is not a certified or independently
audited security product. Scan only targets you own or have explicit authority to assess.

Do not post tokens, real host reports, package inventories, local paths, or sensitive
logs in public issues. Use GitHub's private vulnerability reporting when available;
otherwise open a minimal issue requesting a private contact, without exploit or
sensitive details. Do not send findings to third parties without authorization.

## Boundary

The trusted boundary includes the local OS account, executable and configuration,
private state directory, engine/database provenance, and approved local targets.
Backend JSON and feed files are untrusted. Parsing is bounded and shape-validated;
reports escape content; subprocesses use fixed argument arrays without a shell.
Target configuration can expose files to the trusted backend. Choose it carefully.

The API binds only loopback, rejects non-loopback peers, unexpected Host/Origin,
and proxy use, requires tokens, limits bodies/requests, and serializes HTTP scans.
Do not use tunneling, reverse proxies, public container port mappings, or wildcard
host binds. Loopback HTTP is not encrypted. Same-account processes and local malware
are not isolated by tokens, database files, path hashes, or UI sessions.

Keep state and reports private using OS permissions; package inventories can be
sensitive. SQLite evidence and audit events are local, unencrypted, and not tamper-
evident. They are not forensic chain-of-custody records. Unknown freshness or failed
coverage never means safe. Scanner stdout limits do not bound all backend CPU/RAM
or filesystem I/O. Only trusted engines should be configured.

Hold/restore is not containment. Stop writers. Windows verifies owner SID but not
DACL write grants: private ACL-protected roots are required, shared writable roots
unsupported. Project-access writers are outside the integrity guarantee. POSIX
rejects group/other writable holding directories. Native handles/no-follow traversal
reduce replacement races; they do not make writable project trees adversary-proof.
Review the exact SHA-256, keep backups, and never hold system/privileged files.

Network shares and mapped network drives are unsupported. Resolved UNC targets
are rejected, but mapped drive provenance is not automatically attested. Avoid
network-backed links and mounts. CLI watch processes can overlap other CLI processes;
use one scanner process per state/cache, and one worker for the dashboard.
