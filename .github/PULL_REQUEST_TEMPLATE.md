# What does this change?

<!-- One or two sentences. What's different after this merges? -->

Fixes #

## Why

<!-- What problem does this solve? If it's linked to an issue that already explains it, just say "see issue". -->

## How was it verified?

<!-- Tests you added, commands you ran, what you saw. "Ran the suite" is fine if that's genuinely what you did. -->

## Type

- [ ] Bug fix
- [ ] New detector / detection rule change
- [ ] New feature
- [ ] Documentation
- [ ] Refactor / internal cleanup
- [ ] Performance

## Checklist

- [ ] I've read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] I've signed the [CLA](../CLA.md) (the bot will prompt on your first PR)
- [ ] Tests pass locally
- [ ] New behaviour has tests
- [ ] **No real credentials in the diff** — test fixtures use syntactically valid but non-functional values
- [ ] Docs updated, if behaviour changed

## For detector changes only

- [ ] Added a **true positive** test
- [ ] Added a **near-miss negative** test that must not match
- [ ] Linked the provider's credential-format documentation
- [ ] Checked the pattern compiles under `google-re2` where possible (no catastrophic backtracking)

<!--
A note on review: detector changes get scrutinised more than most code, because a
false positive costs every downstream user review time. It's not a comment on
your work — please don't read pushback as rejection.
-->
