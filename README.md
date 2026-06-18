# nocapsec

> No cap. Just verified vulnerabilities.

Proof engine for security findings. A client (typically an LLM) proposes a vulnerability finding as a structured reproduction bundle; the engine validates the evidence, applies strict policy, executes one deterministic proof rule, and returns a reproducible verdict (`verified`, `not_reproduced`, `inconclusive`, `rejected`, `invalid`). It is not a scanner: it never improvises payloads and never discovers issues on its own.
