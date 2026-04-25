# Model selection (current supported/testable set)

## Purpose

This document defines the current operator-supported provider/model selection set for SIR execution paths that accept model selection (`sir run`, `sir benchmark run`, and workflow dispatch run/benchmark paths).

It is intentionally explicit and bounded.

## Supported providers

- `xai`
- `openai`

## Supported selectable models by provider

### xai

- `grok-3-beta`
- `grok-4-1-fast`
- `grok-4.20-0309-reasoning`
- `grok-4.20-0309-non-reasoning`

### openai

- `gpt-4o-mini`
- `gpt-4.1-mini`
- `gpt-4.1`
- `gpt-5.4-mini`

## Required secret/env var by provider (live mode only)

- `xai` -> `XAI_API_KEY`
- `openai` -> `OPENAI_API_KEY`

Audit/governance-gate-only execution does not require provider secrets.

## Defaults

- default provider: `xai`
- default model: `grok-4-1-fast`

## Selection rule

Only providers/models explicitly listed in this document are currently supported for selection/testing in this bounded round.

Unsupported provider/model combinations fail validation at execution boundaries.

## Historical evidence note

Historical run/archive evidence may contain older provider/model values that were valid for previous rounds (for example older `xai` model defaults).

Those historical rows remain valid historical evidence; they do not expand the current supported selection set.
