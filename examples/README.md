# Examples

These are local reproductions for known advisories. They validate that `nocapsec` can replay evidence against the target you run: either a pinned vulnerable package harness or the affected app version described in that example.

A `verified` result is conditional on that target. The engine owns nonces, OAST tokens, browser policy, and differential contrast, but it does not attest that a client-supplied local app is the genuine upstream deployment. When using an example as evidence, report the exact target provenance, version, setup, and network boundary.

Do not turn synthetic harness success into a broader claim. A dishonest target can echo canaries, sleep on cue, or call OAST directly; nocapsec prevents LLM payload/origin cheating, not target impersonation.
