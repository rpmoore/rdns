---
name: architecture-planner
description: >
  Plan software architecture for a project using domain-driven design and
  separation of concerns. Use when asked to design, decompose, modularize, or
  plan a new project or major feature. Produces module boundaries for UI,
  domain model, application services, persistence, infrastructure, and tests.
  Requires an independent reviewer agent to critique the design, then refines
  the architecture from that review.
---

# Architecture Planner

Create architecture plans that separate business concepts from delivery and
infrastructure concerns. Favor domain-driven design, testable seams, and clear
module ownership.

## Required Workflow

1. Clarify only blocking unknowns. If enough context exists, state assumptions
   and proceed.
2. Draft an initial design in the main thread.
3. Spawn a separate reviewer agent to find holes, coupling risks, missing
   requirements, test gaps, and operational risks.
4. Collaborate with the reviewer by revising the design against each meaningful
   finding.
5. Return the refined plan, plus unresolved tradeoffs and test strategy.

If subagents are unavailable or current runtime policy does not allow spawning
one, stop and ask the user to explicitly allow an independent reviewer agent.
Do not present a final architecture plan without an independent review pass.

## Design Heuristics

- Start from domain language: bounded contexts, aggregates/entities, value
  objects, domain services, events, invariants, and policies.
- Keep domain model free of web, database, framework, queue, cloud, and vendor
  dependencies.
- Put orchestration in application services/use cases. They coordinate domain
  objects, repositories, transactions, auth decisions, and external ports.
- Hide infrastructure behind ports/interfaces: repositories, clocks, ID
  generators, payment/email/search clients, event publishers, feature flags.
- Keep adapters thin: web UI, HTTP controllers, CLI, database implementations,
  message consumers, third-party SDK wrappers.
- Separate read/query models from write/domain models when lifecycle,
  performance, permissions, or shape differ.
- Prefer dependency injection at module boundaries. Inject ports into use cases;
  do not make domain logic reach into globals, frameworks, or concrete clients.
- Define failure modes and consistency boundaries explicitly: transaction scope,
  retries, idempotency, eventual consistency, concurrency, authorization.
- Avoid premature microservices. Split deployable services only when ownership,
  scaling, data boundaries, or reliability requirements justify it.

## Plan Shape

Use this structure unless the user asks for another format:

```markdown
## Assumptions
- ...

## Domain Model
- Bounded contexts:
- Aggregates/entities:
- Value objects:
- Domain services/policies:
- Domain events:
- Invariants:

## Module Boundaries
- `ui`:
- `api` or `delivery`:
- `application`:
- `domain`:
- `persistence`:
- `infrastructure`:
- `shared`:

## Dependency Direction
- ...

## Key Flows
1. ...

## Testing Plan
- Unit tests:
- Contract/adapter tests:
- Integration tests:
- End-to-end tests:
- Test data and fixtures:

## Reviewer Findings And Revisions
- Finding:
  Revision:

## Open Tradeoffs
- ...
```

## Reviewer Agent Prompt

When spawning the reviewer agent, give only the user request, assumptions, and
draft design. Ask for critique, not praise.

```text
Review this software architecture plan. Find holes and flaws.

Focus on:
- broken or unclear domain boundaries
- misplaced responsibilities
- coupling between UI, domain, persistence, and infrastructure
- missing dependency-injection seams
- weak unit-testability
- missing integration-test coverage
- data consistency, transactions, idempotency, concurrency, auth, observability
- overengineering or unjustified service splits

Return findings as:
- Severity: critical/high/medium/low
- Problem
- Why it matters
- Concrete revision

Do not rewrite the whole design unless necessary.
```

## Refinement Rules

- Accept reviewer findings that expose real risk. Revise plan directly.
- Reject findings only with a short rationale tied to requirements or
  constraints.
- If reviewer reveals missing requirements, add assumptions or questions.
- Preserve domain purity when adding testability or infrastructure details.
- Final output must show how review changed the design.
