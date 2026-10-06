"""Historical absence is not proof of remediation."""

from .models import Run


def compare_runs(before: Run, after: Run) -> dict:
    compatible = (
        before.status == after.status == "complete"
        and before.target == after.target
        and before.backend == after.backend
        and bool(before.target_identity)
        and before.target_identity == after.target_identity
        and before.backend_version == after.backend_version
        and before.offline == after.offline
        and bool(before.coverage)
        and sorted(before.coverage) == sorted(after.coverage)
    )
    older = {f.fingerprint: f.to_dict() for f in before.findings}
    newer = {f.fingerprint: f.to_dict() for f in after.findings}
    disappeared = [older[k] for k in sorted(older.keys() - newer.keys())]
    return {
        "comparable": compatible,
        "reason": (
            "Matching complete declared coverage. Absence is not proof of repair."
            if compatible
            else "Incomplete or incompatible coverage; disappearances unresolved."
        ),
        "added": [newer[k] for k in sorted(newer.keys() - older.keys())],
        "persistent": [newer[k] for k in sorted(newer.keys() & older.keys())],
        "no_longer_observed": disappeared if compatible else [],
        "unresolved": [] if compatible else disappeared,
    }
