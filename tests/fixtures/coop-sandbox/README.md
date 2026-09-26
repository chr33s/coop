# coop-sandbox fixtures

Real output of `coop-sandbox` 0.1.0 (protocol 1, containerization 0.45.0),
captured from one sandbox on macOS 27 and used by the `apple_container` unit
tests:

- `version.json` — `coop-sandbox version`
- `inspect-stopped.json` — `coop-sandbox inspect` of a created, stopped sandbox
- `inspect-running.json` — the same sandbox running (live state and effective
  VM configuration)

The sandbox id is `coop-0a1b2c3d-00112233445566ff`, the owner
`0a1b2c3d00112233445566778899aabb`, and the runtime root was rewritten to
`/Users/me/.coop-apple/backends/apple-container-v1/runtime`; the tests
substitute their own values for all three. Regenerate after any change to the
runtime's JSON output, and bump the protocol version for an incompatible one.
