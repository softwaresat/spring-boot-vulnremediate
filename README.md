# VulnRemediate

VulnRemediate is a LangGraph-powered harness for remediating **Spring Boot application** vulnerabilities. It makes deterministic changes first, keeps upgrades reviewable, and leaves any ambiguous remediation for a human or a separately configured coding agent. It refuses to run against a repository that does not declare Spring Boot through its parent POM, BOM, or starter dependencies.

Its workflow is:

1. Inspect the repository and update explicitly configured Docker, Helm, and Spring Boot baselines.
2. Parse GitHub Dependabot alert exports and Trivy filesystem/container JSON reports.
3. Build a **parent-first** Maven plan: change the Spring Boot parent/BOM or dependency-management entry before a child dependency.
4. Apply the plan, run Maven verification and optional scans, then commit/push only when requested.

No vendor endpoint, registry, or model is baked in. The harness never invents versions: baseline versions are supplied in configuration, while dependency recommendations must come from a scan artifact.

## Install

```bash
python -m pip install -e '.[dev]'
```

## Run

Start with a dry run:

```bash
vulnremediate run --repo . --scan-report dependabot-alerts.json
```

## CLI commands

```text
vulnremediate init                 # create .vulnremediate.json
vulnremediate export-dependabot    # retrieve open GitHub Dependabot alerts
vulnremediate plan                 # non-mutating graph execution and JSON plan
vulnremediate remediate --apply    # change, verify, then optionally push a branch
vulnremediate run                  # compatibility alias for remediate
```

Apply changes and verify:

```bash
vulnremediate run --repo . --scan-report gl-dependency-scanning-report.json --apply
```

To commit and push after successful verification:

```bash
vulnremediate run --repo . --scan-report report.json --apply --push
```

To retrieve open GitHub Dependabot alerts directly (requires a token with Dependabot alerts read access):

```bash
vulnremediate run --repo . --github-repository owner/repository --apply --branch security/remediate-alerts --push
```

For blocked cases, add a model that supports the OpenAI Responses API. The agent is deliberately constrained to request Maven diagnostics or document a manual review; deterministic code remains the only component that edits a repository.

```bash
vulnremediate run --repo . --scan-report dependabot-alerts.json --apply --agent-model your-model-id
```

The complete, versioned system and task prompts are in [`vulnremediate/prompts.py`](vulnremediate/prompts.py).

`--push` requires a clean repository before the run and an already configured Git remote. The command prints a JSON audit record, including every command and file edit. The included GitHub Actions workflow uploads Trivy reports and publishes SARIF results to GitHub code scanning; Dependabot continuously supplies Maven and Docker advisories.

## Configuration

Copy [`examples/vulnremediate.json`](examples/vulnremediate.json) to `.vulnremediate.json` in the target repository. All baseline fields are optional. `scan_command` is a command template run after Maven verification; `{report}` is replaced by the artifact path.

## Safety model

* Dry-run is the default.
* Only files already discovered in the repository can be edited.
* Maven version resolution uses `mvn help:effective-pom` before editing a child dependency.
* The target must be a Spring Boot application (`spring-boot-starter-parent`, `spring-boot-dependencies`, or a `spring-boot-starter-*` dependency).
* Each finding has an explicit remediation plan: Spring Boot parent, dependency-management entry, Maven version property, direct dependency, or a documented blocked reason.
* A plan is skipped when no scanner-provided fixed version exists.
* Pushes are opt-in, can target a fresh branch, and happen only after successful verification.
