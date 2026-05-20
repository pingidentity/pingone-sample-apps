---
name: review-conventions
description: PingOne Go SDK pull request and code review conventions — use when reviewing PRs or code changes in this repo
---

## PR scope and title

- One logical concern per PR. Related utilities can share a PR; unrelated API endpoints should be separate.
- Title format: `<Verb> <description>` where verb is one of **Add**, **Update**, **Fix**, or **Remove**.
  - Example: `Add support for DaVinci Flow Policies API`

## Generated code — hard rule

Files in `pingone-go-client/pingone/` are auto-generated. **Never approve manual changes to that directory.** If a change is needed, it must go through the OpenAPI spec + generator.

## Verification checklist before approving

```bash
go mod tidy        # go.mod/go.sum should be clean after this
make build         # must exit 0
make fmt           # no files modified
make lint          # must exit 0
make test          # must exit 0
make security      # review any new findings (runs with -no-fail)
```

## Documentation requirements

- All exported functions need a doc comment.
- New SDK functionality needs an example in `examples/` with a README.
- No API keys, tokens, or secrets in code or test files — credentials go in env vars.

## Test requirements

- New exported functions in hand-written packages (`config/`, `oauth2/`, `oidc/`) should have unit tests.
- New API functionality in `pingone/` should have integration tests in `pingone/test/` using the `testframework` suites.
- Integration tests must not hardcode credentials.
