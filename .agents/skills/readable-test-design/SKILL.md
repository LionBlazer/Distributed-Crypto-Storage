---
name: readable-test-design
description: Design or refactor tests as readable examples of observable behavior at the correct unit, API, contract, integration, or peer-protocol boundary. Use when adding, changing, or reviewing repository tests.
---

# Readable test design

Adapted from SpaceTimeAutocoder2. Make each test explain one observable behavior at
the boundary that owns it, using the chosen language's test framework.

- Use API examples for consumer-visible public contracts, contract tests for shared
  implementation guarantees, integration tests for real storage/process/protocol
  boundaries, and unit tests for isolated domain behavior.
- Arrange the smallest valid scenario, keep one primary Act visible, then assert
  concrete results. Label non-trivial Arrange, Act, and Assert sections using the
  language's normal comment syntax. Keep cleanup in resource or lifecycle owners.
- Name tests for the condition and observable result. Helpers may build fixtures but
  should not hide the behavior or reproduce the implementation algorithm.
- Assert through public results, owned state, or side effects; avoid private-state
  inspection in API examples and assertions limited to non-null or size alone.
- For asynchronous behavior, wait for an observable condition with a bounded timeout;
  do not use arbitrary sleeps. Keep fixtures reproducible and near their scenarios.

For peer and cryptographic boundaries, select cases from the affected requirement:
tampering, omitted records, invalid proofs, stale versions, unauthorized writes,
peer loss, recovery, or resource exhaustion. These are targeted scenarios, not a
requirement to add the entire matrix to every change. Never use real secrets or
participant data in fixtures.

Keep non-hermetic external-system tests explicit and opt-in. Run focused and affected
tests using actual repository commands; distinguish compile checks, behavior tests,
and unexecuted external scenarios when reporting results.
