---
id: VK-6tom
title: "Pin VAOS CI runner and upgrade GitHub Actions"
status: in_progress
priority: 3
type: chore
created_at: 2026-09-18T01:14:09Z
created_by: speed
updated_at: 2026-09-18T01:41:19Z
content_hash: "sha256:8edc2e2d6757c691ef0a6358672ac261648b0d2f600327d6c4ed69cf75c38dd3"
assignee: dev-VK-6tom
---

## Description
GitHub CI passed for merge commit `b97db595773311a0b04bf461bb6f47929c99138b`, but GitHub emitted two forward-compatibility warnings:

- `ubuntu-latest` will begin migrating to Ubuntu 26 on 2026-10-19.
- `actions/checkout@v4` and `actions/setup-go@v5` target Node.js 20 and are currently forced onto Node.js 24.

The workflow should be made explicit before the runner image changes automatically.

## Scope

- Update `.github/workflows/ci.yml`.
- Pin the CI runner image to a tested Ubuntu version rather than relying on the `ubuntu-latest` migration.
- Upgrade `actions/checkout` and `actions/setup-go` to maintained major versions that natively target the current Actions runtime.
- Run the complete Go CI commands locally and verify the resulting GitHub Actions run.

## Acceptance Criteria

- [ ] AC #1: CI uses an explicit, supported Ubuntu runner image.
- [ ] AC #2: CI uses maintained action versions without Node.js 20 deprecation warnings.
- [ ] AC #3: `go mod tidy`, the dependency-diff check, `go build ./...`, and `go test ./...` pass.
- [ ] AC #4: A pull-request CI run completes successfully without the runner-migration or Node.js runtime warnings.

## Out of Scope

- Changing application code.
- Changing the Agentic JWT implementation.

## Acceptance Criteria


## Design


## Notes
## Implementation Evidence

Summary: Pinned VAOS CI to `ubuntu-24.04` and upgraded `actions/checkout` and `actions/setup-go` to their maintained v7 majors in story worktree `/Users/speed/vaos-kernel/.claude/worktrees/dev-VK-6tom`.

Commit SHA: d7ac45ee0b5272994f476e14f9857abc344f9dc8

Pull request: https://github.com/jmanhype/vaos-kernel/pull/2

Evidence directory: `/Users/speed/Jev/vaos-auth51-jev-fit/evidence/vk-6tom-20260918`

Commands run:
- `grep` configuration assertions for `ubuntu-24.04`, `actions/checkout@v7`, and `actions/setup-go@v7`
- Python YAML parse plus expected job assertions
- `go mod tidy`
- `git diff --exit-code -- go.mod go.sum`
- `go build ./...`
- `go test ./...`
- staged redacted `gitleaks protect --staged`
- GitHub push and pull_request CI verification
- GitHub Actions job annotation verification

### CI/Test Results

- Configuration gates: PASS (`configuration-gates.txt`, SHA-256 `f77ebbc9b1517ed5ebbf0d053d1a753dbecc6e71a92b51c2fc6cf2093c7eacbb`)
- Local CI: PASS (`local-ci.txt`, SHA-256 `834946cac603e6f84125abafde15e8f5df5d0a6826aa63d9e45a07fdfb5792ff`)
- Action metadata: checkout v7.0.1 and setup-go v7.0.0 both declare Node.js 24 (`action-metadata.txt`, SHA-256 `707c75ba29135ff79894d66ca04f5160c2f04e58cae56354c92bfe549120e3c2`)
- PR CI: push and pull_request runs completed successfully for commit `d7ac45ee0b5272994f476e14f9857abc344f9dc8` (`pr-ci.json`, SHA-256 `633211c4ea0ecba593518cadbc6ae1c6782cf8efa56a5f27d149865330cb86ec`)
- Runner verification: both jobs report the `ubuntu-24.04` label.
- Warning verification: both job annotation arrays are empty.
- Staged credential scan: PASS, no leaks.

### AC Verification

[x] AC #1: CI uses the explicit supported `ubuntu-24.04` runner image.
[x] AC #2: CI uses maintained checkout/setup-go v7 actions without Node.js 20 deprecation warnings.
[x] AC #3: `go mod tidy`, dependency-diff check, `go build ./...`, and `go test ./...` pass.
[x] AC #4: push and pull_request CI runs pass on `ubuntu-24.04` with zero job annotations.

## History
- 2026-09-18T01:35:48Z status: open -> in_progress
- 2026-09-18T01:35:48Z claimed by dev-VK-6tom
- 2026-09-18T01:41:19Z status: in_progress -> in_progress

## Links


## Comments
