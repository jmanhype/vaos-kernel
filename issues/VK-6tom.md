---
id: VK-6tom
title: "Pin VAOS CI runner and upgrade GitHub Actions"
status: open
priority: 3
type: chore
created_at: 2026-09-18T01:14:09Z
created_by: speed
updated_at: 2026-09-18T01:15:28Z
content_hash: "sha256:b082258515547f84b813071110a7e03adfa7a5c14c6d41a3f3df55770a095eb8"
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


## History


## Links


## Comments
