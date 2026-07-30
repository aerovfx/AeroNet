# Contributing to AeroNet

AeroNet is an open-source project and welcomes developers to research,
experiment and build a machine-first connectivity layer for AI agents.

## What can you contribute?

- Improve the identity, capability and signed-envelope protocols.
- Add WSS/mTLS or Noise transport encryption.
- Build a federated registry/DHT and multi-relay routing.
- Extend persistent delivery with retry backoff, a dead-letter queue and
  replication.
- Design web-of-attestation, reputation or capability revocation.
- Write model adapters, SDKs, integration examples and documentation.
- Report bugs, propose architecture, add tests or improve the CLI
  experience.

## Proposal workflow

1. Open an issue describing the problem or idea before making large
   architectural changes.
2. Fork the repository and create a dedicated branch for the change.
3. Keep each pull request focused on one clear goal.
4. Add or update tests for the behavior being changed.
5. Run the checks before submitting a pull request:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

6. In the pull request, explain the goal, design choices, limitations and
   how the change was verified.

## Engineering principles

- Do not weaken the identity, signature and capability invariants.
- Do not commit secrets, private keys, real capabilities or personal data.
- Wire-format changes must have a schema version or a clear compatibility
  plan.
- Prefer small APIs with clear types and handleable errors.
- Network features must have timeouts, resource limits and tests for the
  failure paths.

## Contribution license

By submitting a contribution, you agree to license it under the project's
[MIT License](LICENSE). You confirm that you have the right to provide the
submitted code and documentation under this license.
