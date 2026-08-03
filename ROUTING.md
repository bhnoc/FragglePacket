# Model routing notes

Live ladder is pulled per session from the proxy's `/v1/models`; never hardcode
IDs here. This file records what actually worked per task type so routing
improves over sessions rather than being re-guessed.

Format: `task-type → model that worked (what failed) — date, one-line why`

| Task type | Routed to | Date | Why |
| --- | --- | --- | --- |
| Rust CLI refactor, mechanical move of 2551 lines into a module tree | sonnet-5 | 2026-08-02 | Large but spec-driven with a hard parity gate to check against. Landed clean on the first pass, main.rs 2551→21 lines, 37/37 gate checks green, no behavior drift. Cheapest capable generalist; no cascade needed. |
| Implementing a gap with explicit written acceptance criteria + a locking test | sonnet-5 | 2026-08-02 | Sprint 1 P0 work. The acceptance criteria do the specification work, so the model is executing rather than designing. |

## Notes

- The gap list's acceptance criteria are unusually precise, which makes most of
  this build execution rather than design work. That keeps the default lane at
  sonnet-5 rather than an opus tier.
- Judge/verify passes on P0 correctness claims should run at opus-5, ideally
  cross-provider (`gpt-5.6`), since a worker grading its own class of work is
  theater. P0 here means "can produce a materially false diagnosis", so an
  agent's self-report is not sufficient evidence.
- Do not route to any opus-4.x: opus-5 is the same $5/$25 and strictly better.
  Likewise every older sonnet at $3/$15 is dominated by sonnet-5 at $2/$10.
