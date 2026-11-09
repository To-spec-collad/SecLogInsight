from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


FIELDS = [
    "slug",
    "commit_sha",
    "status",
    "baseline_vulnerability_count",
    "post_vulnerability_count",
    "remediation_success",
    "resolver_conflict",
    "tests_passed",
    "osv_after_passed",
    "changed_package_count",
    "remediation_duration_seconds",
    "duration_seconds",
    "started_at",
    "finished_at",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    root = Path(args.input)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for path in sorted(root.rglob("result.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                results.append(data)
            else:
                results.append({"slug": path.parent.name, "status": "invalid_result"})
        except (OSError, json.JSONDecodeError):
            results.append({"slug": path.parent.name, "status": "invalid_result"})

    rows = [{field: result.get(field, "") for field in FIELDS} for result in results]
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    eligible = [
        result
        for result in results
        if isinstance(result.get("baseline_vulnerability_count"), int)
        and result["baseline_vulnerability_count"] > 0
    ]
    summary = {
        "project_count": len(results),
        "eligible_project_count": len(eligible),
        "remediation_success_count": sum(bool(item.get("remediation_success")) for item in eligible),
        "resolver_conflict_count": sum(bool(item.get("resolver_conflict")) for item in eligible),
        "test_pass_count": sum(bool(item.get("tests_passed")) for item in results),
        "osv_after_pass_count": sum(bool(item.get("osv_after_passed")) for item in results),
        "results": results,
    }
    durations = [
        item["duration_seconds"]
        for item in results
        if isinstance(item.get("duration_seconds"), (int, float))
    ]
    summary["total_duration_seconds"] = sum(durations)
    summary["mean_duration_seconds"] = (
        sum(durations) / len(durations) if durations else None
    )
    if eligible:
        summary["remediation_success_rate"] = summary["remediation_success_count"] / len(eligible)
        summary["resolver_conflict_rate"] = summary["resolver_conflict_count"] / len(eligible)
    else:
        summary["remediation_success_rate"] = None
        summary["resolver_conflict_rate"] = None
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
