# Python dependency remediation benchmark

This bundle is designed for GitHub Actions. It evaluates `pip-audit` as the
remediation baseline and uses OSV-Scanner as an independent post-remediation
rescan. It does not require Python, pip, uv, or PyCharm on the local computer.

## Files

- `.github/workflows/dependency-remediation.yml`: manual matrix workflow.
- `data/projects.csv`: 32 real open-source Python repositories.
- `tools/remediatebench/run_project.py`: runs one project experiment.
- `tools/remediatebench/aggregate.py`: combines project artifacts.

## How to use

1. Open **Actions -> Python dependency remediation benchmark**.
2. Select **Run workflow** on the `main` branch.
3. Download the `remediation-results` artifact after the matrix completes.

The workflow is manual by design. It does not run on every push, so it will not
consume Actions minutes unexpectedly. Each matrix entry is isolated and a
failed clone, install, scan, or test is recorded in its artifact instead of
terminating the whole batch.

## Metrics

The aggregated `summary.csv` and `summary.json` contain:

- baseline and post-remediation vulnerability counts;
- remediation success (`baseline_count > 0` and `post_count == 0`);
- resolver conflict detection;
- project test status;
- changed package count and remediation duration;
- elapsed time and failure stage.

Projects with zero baseline vulnerabilities remain in the output, but are not
used as the denominator for remediation success rate. The raw per-project
reports are retained so the final paper can distinguish no-vulnerability,
fixed, unresolved, conflict, install-failure, and test-failure cases.

## Reproducibility notes

The runner records the checked-out commit SHA, Python version, tool versions,
commands, timestamps, dependency snapshots, scanner outputs, and test logs.
The experiment is tied to the exact repository revision observed by GitHub Actions
rather than a moving branch name.

This is an experiment harness, not a claim that the benchmark has already been
executed. Run the workflow first, then use the generated results for analysis.
