# Paymenter Product Email Template SSTI

Paymenter commit `b7b7a89e9eb6b8583b16c8d1f9ef6036dfe19e5a` renders a product-controlled
`email_template` as Blade during service activation. The rendered email body is
materialized in `EmailLog`, so the proof is stored and multi-step rather than reflected:

1. Store the product email snippet.
2. Trigger service-created notification rendering.
3. Read the latest email log body.

This example uses a tiny local Paymenter-shaped harness for that write/trigger/read flow.
It proves the `ssti.stored` validator contract without requiring a full Laravel install.
For a real Paymenter instance, keep the same evidence shape but replace the setup,
trigger, and observe requests with the authenticated HTTP requests from that deployment.

## Reproduce

From the `nocapsec` repo:

```bash
go run ./examples/ssti-stored-paymenter-email
```

The example starts a local target and patches `evidence.json` from port `0` to the chosen
listener port before verification.

The evidence has one `setup_request` plus an `injection` slot (`email_template` form field),
one trigger request, and one observe request. The engine plants a literal control first,
then a Blade arithmetic payload (`{{ {{ssti_marker}} }}`), triggers rendering after each
setup, and verifies that only the candidate observation contains the computed product.
