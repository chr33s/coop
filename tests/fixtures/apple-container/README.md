# Apple Container CLI fixtures

Inputs for the `src/apple_container` parser tests.

| File | Source |
|---|---|
| `version-1.4.1.txt` | Captured: `container --version`, Apple Container 1.4.1 (Homebrew), macOS 27.0 arm64, 2026-09-25. |
| `machine-create-help-1.4.1.txt` | Captured: `container machine create --help`, same runtime. Shows that stock 1.4.1 has no `--network` / `--no-ssh-agent`. |
| `machine-inspect-1.4.1.json` | Synthetic. Shape follows `InspectOutput` in `Sources/ContainerCommands/Machine/MachineInspect.swift` at tag `1.4.1` (commit `9eacc197`), encoded with `.prettyPrinted, .sortedKeys`. |
| `version-coop-fdddb59.txt` | Captured: `container --version` from the `vendor/container` fork at `fdddb59`, built with `RELEASE_VERSION=1.4.1+coop.fdddb59` (see docs/backends.md), macOS 27.0 arm64, 2026-09-25. |
| `machine-create-help-coop-fdddb59.txt` | Captured: `container machine create --help`, same build. Lists `--network` and `--no-ssh-agent`. |
| `machine-inspect-extended.json` | Synthetic. Shape follows `InspectOutput` in `Sources/ContainerCommands/Machine/MachineInspect.swift` of the fork at `fdddb59`: the 1.4.1 fields plus `network` (omitted for the built-in network) and `sshAgentForwarding`. |
| `machine-list-1.4.1.json` | Synthetic. Shape follows `PrintableMachine` in `MachineList.swift` at tag `1.4.1`. |
| `container-inspect-1.4.1.json` | Synthetic. Shape follows `ManagedContainer` / `ContainerConfiguration` at tag `1.4.1`, with the mounts, network, and `ssh = true` that `MachinesService.toContainerConfig` sets for a stock machine created with the default `--home-mount rw`. |

Identifiers in the synthetic files are synthetic. Replace them with captured
output (sanitized) from a running fork service (spec WP-0).
