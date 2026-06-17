# Cerbos Agent Plugin

This plugin packages a focused agent workflow for Cerbos maintainers and users. It is designed to be useful in Codex, Claude Code, Claude Cowork, Copilot-style coworkers, and other `SKILL.md`-compatible harnesses.

The plugin does not add a runtime dependency to Cerbos. It gives agents a precise operating procedure, expected outputs, and plugin evals so maintainers can decide whether agent-produced work is good enough to accept.

## What It Includes

- Codex and Claude plugin manifests.
- A Cerbos-specific skill at `skills/cerbos-policy-author/SKILL.md`.
- Plugin eval cases in `evals/cerbos-policy-author/cases.jsonl`.
- Privacy-safe measurement guidance for teams that want production plugin metrics.

## Manifest Compatibility

The Codex and Claude manifests use `skills: ./skills/`, which is resolved from the plugin root by the plugin manifest contract. The Codex manifest validates with the local plugin validator used for this contribution.

## Primary Workflows

- Policy intent capture.
- Fixture matrix generation.
- Decision review.
- Regression gap analysis.

## Eval Cases

- `policy-matrix`: Create a Cerbos fixture matrix for project admins, members, and guests.
- `deny-review`: Review a Cerbos policy where a member can unexpectedly delete a project.
- `pii-fixtures`: Rewrite policy test fixtures to avoid production user data.

## Install In An Agent Harness

Use this plugin directory directly from the repository when your harness supports local or Git-backed plugin sources. The plugin root is:

```text
plugins/cerbos-policy-author
```

For Telvine-backed distribution and metrics, the Telvine CLI is published as [`telvine` on npm](https://www.npmjs.com/package/telvine):

```bash
npm i -g telvine
telvine login
telvine publish ./plugins/cerbos-policy-author
telvine plugins metrics
```

## Telemetry Boundary

The plugin should only record metadata about plugin execution and eval outcomes. Do not record prompts, source files, request bodies, connector payloads, credentials, model outputs, or production user data.
