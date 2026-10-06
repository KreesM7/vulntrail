# Operations

Run as an ordinary user. Keep engine binaries and databases outside scanned
projects. Review configuration; provision databases explicitly while online. Default
offline scans suppress database, Java, VEX, version, and update checks and use an
empty trusted config/ignore file/module directory. This limits incidental backend
behavior but does not enforce an OS sandbox or firewall.

Refresh data intentionally using Trivy's official commands, then rescan. Database
age uses cached metadata, not report import time. Missing/unknown metadata and stale
data are visible warnings. Follow upstream schema/version compatibility rules when
transferring caches. Integrity/provenance must be checked separately.

`watch` is opt-in, foreground, interval-after-completion. Stop with Ctrl+C. One watch
process per target/state/cache is recommended; don't overlap with dashboard scans.
Use an OS scheduler under your own account for startup/rotation. No telemetry or
cloud storage is intentionally added by VulnTrail. Backend flags are not packet-level
verification of zero egress. Other trusted dependencies/OS components have their
own behavior.

## State and recovery

State lives in configured `state_dir/evidence.sqlite3`, with parameterized SQL and
append-only run IDs. There is no encryption, signature, or automatic retention.
Stop the service before a filesystem backup, including any SQLite journal/WAL files;
prefer SQLite's backup facility for a running database. Reports and feeds may contain
private inventories. Delete only the runs you intend using authenticated local APIs.
Keep backups if you need recovery; deleted runs have no built-in recycle bin.

Hold/restore writes `.vulntrail-hold` under your explicitly selected project.
Prepared manifests allow recovery when a post-move metadata write fails. Inspect
the holding area before retrying; never edit manifests to bypass validation. Hold
directories are not excluded from backend scans and must not be mistaken for isolation.

## Container CLI

The Dockerfile packages only VulnTrail, not Trivy or vulnerability data. Build it
yourself, mount a verified Linux-compatible engine, compatible database, local
project, and private writable state. Mount project/cache read-only for normal scans.
Use `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, and a
non-root UID matching mounted directory permissions. Never mount the Docker socket.

```sh
docker build -t vulntrail:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/container-config.yaml:/config.yaml:ro" \
  -v "/absolute/project:/target:ro" \
  -v "/absolute/state:/state" \
  -v "/absolute/cache:/cache:ro" \
  -v "/absolute/verified-trivy:/backend/trivy:ro" \
  vulntrail:local --config /config.yaml scan app
```

The user-created container configuration uses `targets: {app: /target}`,
`state_dir: /state`, `cache_dir: /cache`, `trivy_path: /backend/trivy`, and `offline: true`.
Ensure the binary is compatible with the image's Linux architecture and libc.
The dashboard inside this image is not exposed: loopback-only peer checks deliberately
reject ordinary container port forwarding. Use the dashboard natively. Docker runtime
behavior must be verified on your host; local development lacked a Docker runtime.
