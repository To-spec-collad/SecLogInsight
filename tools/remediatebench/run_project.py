from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], cwd: Path | None, log_path: Path, timeout: int = 900) -> dict:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout or ""
        log_path.write_text(output, encoding="utf-8", errors="replace")
        return {
            "command": cmd,
            "returncode": completed.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output": output,
            "timed_out": False,
        }
    except FileNotFoundError as exc:
        output = f"{exc}\n"
        log_path.write_text(output, encoding="utf-8", errors="replace")
        return {
            "command": cmd,
            "returncode": 127,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output": output,
            "timed_out": False,
            "missing_command": True,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if not isinstance(output, str):
            output = ""
        output += f"\nTIMEOUT after {timeout} seconds\n"
        log_path.write_text(output, encoding="utf-8", errors="replace")
        return {
            "command": cmd,
            "returncode": 124,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output": output,
            "timed_out": True,
        }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def parse_pip_audit(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"parseable": False, "vulnerability_count": None}
    dependencies = data if isinstance(data, list) else data.get("dependencies", [])
    count = 0
    for dependency in dependencies:
        if isinstance(dependency, dict):
            vulns = dependency.get("vulns", dependency.get("vulnerabilities", []))
            if isinstance(vulns, list):
                count += len(vulns)
    return {"parseable": True, "vulnerability_count": count}


def package_map(path: Path) -> dict[str, str]:
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    result = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("name") and row.get("version"):
            result[row["name"].lower().replace("_", "-")] = row["version"]
    return result


def count_diff(before: dict[str, str], after: dict[str, str]) -> int:
    keys = set(before) | set(after)
    return sum(before.get(key) != after.get(key) for key in keys)


def detect_conflict(output: str) -> bool:
    text = output.lower()
    return any(
        marker in text
        for marker in (
            "resolutionimpossible",
            "dependency conflict",
            "cannot install",
            "conflicting dependencies",
        )
    )


def detect_test_command(repo: Path, python: Path) -> list[str]:
    if (repo / "pytest.ini").exists() or (repo / "tox.ini").exists() or (repo / "pyproject.toml").exists():
        return [str(python), "-m", "pytest", "-q"]
    return [str(python), "-m", "unittest", "discover", "-v"]


def save_failure(metadata: dict, status: str, out: Path) -> int:
    metadata["status"] = status
    metadata["finished_at"] = now()
    metadata["duration_seconds"] = round(
        time.monotonic() - metadata["_started_monotonic"], 3
    )
    metadata.pop("_started_monotonic", None)
    write_json(out / "result.json", metadata)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slug", required=True)
    parser.add_argument("--repo-url", required=True)
    parser.add_argument("--ref", default="")
    parser.add_argument("--output-root", default="artifacts")
    args = parser.parse_args()

    out = Path(args.output_root) / args.slug
    repo = out / "repo"
    venv = out / "venv"
    out.mkdir(parents=True, exist_ok=True)
    metadata = {
        "slug": args.slug,
        "repo_url": args.repo_url,
        "requested_ref": args.ref,
        "started_at": now(),
        "platform": platform.platform(),
        "python": sys.version,
        "stages": {},
    }
    metadata["_started_monotonic"] = time.monotonic()

    clone_cmd = ["git", "clone", "--depth", "1"]
    if args.ref:
        clone_cmd += ["--branch", args.ref]
    clone_cmd += [args.repo_url, str(repo)]
    metadata["stages"]["clone"] = run(clone_cmd, None, out / "clone.log", 600)
    if metadata["stages"]["clone"]["returncode"] != 0:
        return save_failure(metadata, "clone_failed", out)

    sha = run(["git", "rev-parse", "HEAD"], repo, out / "commit.log", 60)
    metadata["commit_sha"] = sha["output"].strip()
    metadata["stages"]["venv"] = run([sys.executable, "-m", "venv", str(venv)], None, out / "venv.log", 300)
    if metadata["stages"]["venv"]["returncode"] != 0:
        return save_failure(metadata, "venv_failed", out)

    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    pip = [str(python), "-m", "pip"]
    metadata["stages"]["bootstrap"] = run(pip + ["install", "--upgrade", "pip", "setuptools", "wheel"], repo, out / "bootstrap.log", 600)
    if metadata["stages"]["bootstrap"]["returncode"] != 0:
        return save_failure(metadata, "bootstrap_failed", out)

    metadata["stages"]["install_project"] = run(pip + ["install", "-e", "."], repo, out / "install-project.log", 1200)
    project_installed = metadata["stages"]["install_project"]["returncode"] == 0
    if metadata["stages"]["install_project"]["returncode"] != 0:
        requirements = repo / "requirements.txt"
        if not requirements.exists():
            requirements = next(iter(sorted(repo.glob("requirements*.txt"))), None)
        if requirements:
            metadata["stages"]["install_requirements"] = run(pip + ["install", "-r", str(requirements)], repo, out / "install-requirements.log", 900)
            project_installed = metadata["stages"]["install_requirements"]["returncode"] == 0
    if not project_installed:
        return save_failure(metadata, "install_failed", out)

    metadata["stages"]["install_tools"] = run(
        pip + ["install", "pip-audit", "pipdeptree", "pytest"],
        repo,
        out / "install-tools.log",
        600,
    )
    if metadata["stages"]["install_tools"]["returncode"] != 0:
        return save_failure(metadata, "tools_failed", out)

    freeze_before = run(pip + ["list", "--format=json"], repo, out / "freeze-before.log", 120)
    (out / "dependencies-before.json").write_text(freeze_before["output"], encoding="utf-8", errors="replace")
    metadata["stages"]["tree_before"] = run([str(bindir / "pipdeptree"), "--json-tree"], repo, out / "tree-before.log", 180)

    audit_before = run([str(bindir / "pip-audit"), "--progress-spinner", "off", "-f", "json"], repo, out / "pip-audit-before.log", 600)
    (out / "pip-audit-before.json").write_text(audit_before["output"], encoding="utf-8", errors="replace")
    fix_cmd = [str(bindir / "pip-audit"), "--progress-spinner", "off", "--fix"]
    metadata["stages"]["remediation"] = run(fix_cmd, repo, out / "remediation.log", 900)

    freeze_after = run(pip + ["list", "--format=json"], repo, out / "freeze-after.log", 120)
    (out / "dependencies-after.json").write_text(freeze_after["output"], encoding="utf-8", errors="replace")
    metadata["stages"]["tree_after"] = run([str(bindir / "pipdeptree"), "--json-tree"], repo, out / "tree-after.log", 180)
    audit_after = run([str(bindir / "pip-audit"), "--progress-spinner", "off", "-f", "json"], repo, out / "pip-audit-after.log", 600)
    (out / "pip-audit-after.json").write_text(audit_after["output"], encoding="utf-8", errors="replace")

    osv = shutil.which("osv-scanner")
    if osv:
        metadata["stages"]["osv_after"] = run([osv, "scan", "source", "-r", str(repo)], repo, out / "osv-after.log", 600)
    else:
        metadata["stages"]["osv_after"] = {
            "command": ["osv-scanner"],
            "returncode": 127,
            "duration_seconds": 0,
            "output": "osv-scanner not found",
            "missing_command": True,
        }

    metadata["stages"]["tests"] = run(
        detect_test_command(repo, python),
        repo,
        out / "tests.log",
        900,
    )
    before = parse_pip_audit(out / "pip-audit-before.json")
    after = parse_pip_audit(out / "pip-audit-after.json")
    before_packages = package_map(out / "dependencies-before.json")
    after_packages = package_map(out / "dependencies-after.json")
    remediation_output = metadata["stages"]["remediation"].get("output", "")
    metadata.update(
        {
            "baseline_vulnerability_count": before["vulnerability_count"],
            "post_vulnerability_count": after["vulnerability_count"],
            "audit_before_parseable": before["parseable"],
            "audit_after_parseable": after["parseable"],
            "remediation_success": bool(before["vulnerability_count"] is not None and before["vulnerability_count"] > 0 and after["vulnerability_count"] == 0),
            "resolver_conflict": detect_conflict(remediation_output),
            "changed_package_count": count_diff(before_packages, after_packages),
            "remediation_duration_seconds": metadata["stages"]["remediation"].get(
                "duration_seconds"
            ),
            "tests_passed": metadata["stages"]["tests"]["returncode"] == 0,
            "osv_after_passed": metadata["stages"]["osv_after"].get("returncode") == 0,
            "finished_at": now(),
            "duration_seconds": round(
                time.monotonic() - metadata["_started_monotonic"], 3
            ),
        }
    )
    metadata.pop("_started_monotonic", None)
    metadata["status"] = "completed"
    write_json(out / "result.json", metadata)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
