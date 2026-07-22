# Provenance of this fixture

`plan.json` was **generated**, not hand-written:

```
tofu init
tofu plan -out=tfplan.bin
tofu show -json tfplan.bin > plan.json
```

OpenTofu v1.12.5, hashicorp/aws ~> 5.0, 2026-07-22. `main.tf` is the source config.

This matters. Hand-written fixtures let four bugs through the declared-surface parser
earlier in this build, and a hand-written plan would have encoded two things wrong:

1. **`format_version` is `1.2`.** Phase 0's grounding recorded the Terraform JSON format as
   `1.0`. A fixture written from that note would have pinned the wrong version.
2. **`policy` is a JSON *string*, not a nested object.** `jsonencode(...)` in the config
   becomes a string in the plan, so a parser must decode twice. A hand-written fixture would
   most likely have embedded a dict and the double-decode bug would have shipped.

Provider credentials are mocked (`access_key = "mock"`) and no AWS API was contacted;
`skip_credentials_validation` and friends are set. The plan was never applied.
