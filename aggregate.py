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
    "tests_before_passed",
    "tests_passed",
    "osv_before_passed",
    "osv_after_passed",
    "injected_package",
    "injected_version",
    "injected_advisory",
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

    rows = []
    for result in results:
        injection = result.get("injection") or {}
        row = {field: result.get(field, "") for field in FIELDS}
        row["injected_package"] = injection.get("package", "")
        row["injected_version"] = injection.get("version", "")
        row["injected_advisory"] = injection.get("advisory", "")
        rows.append(row)
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
    controlled = [result for result in results if result.get("injection", {}).get("mode") == "controlled"]
    summary = {
        "project_count": len(results),
        "eligible_project_count": len(eligible),
        "controlled_injection_project_count": len(controlled),
        "remediation_success_count": sum(bool(item.get("remediation_success")) for item in eligible),
        "resolver_conflict_count": sum(bool(item.get("resolver_conflict")) for item in eligible),
        "tests_before_pass_count": sum(bool(item.get("tests_before_passed")) for item in results),
        "test_pass_count": sum(bool(item.get("tests_passed")) for item in results),
        "osv_before_pass_count": sum(bool(item.get("osv_before_passed")) for item in results),
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
    summary["tests_before_pass_rate"] = (
        summary["tests_before_pass_count"] / len(results) if results else None
    )
    summary["tests_after_pass_rate"] = (
        summary["test_pass_count"] / len(results) if results else None
    )
    summary["osv_before_pass_rate"] = (
        summary["osv_before_pass_count"] / len(results) if results else None
    )
    summary["osv_after_pass_rate"] = (
        summary["osv_after_pass_count"] / len(results) if results else None
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
