# Apple Container CLI fixtures

Inputs for the `src/apple_container` parser tests.

| File | Source |
|---|---|
| `version-1.4.1.txt` | Captured: `container --version`, Apple Container 1.4.1 (Homebrew), macOS 27.0 arm64, 2026-09-25. |
| `machine-create-help-1.4.1.txt` | Captured: `container machine create --help`, same runtime. Shows that stock 1.4.1 has no `--network` / `--no-ssh-agent`. |
| `machine-inspect-1.4.1.json` | Synthetic. Shape follows `InspectOutput` in `Sources/ContainerCommands/Machine/MachineInspect.swift` at tag `1.4.1` (commit `9eacc197`), encoded with `.prettyPrinted, .sortedKeys`. |
| `machine-inspect-extended.json` | Synthetic. The 1.4.1 shape plus the **proposed** `network` and `sshAgentForwarding` fields from the required runtime extension (spec §7.1). No released runtime emits these yet. |
| `machine-list-1.4.1.json` | Synthetic. Shape follows `PrintableMachine` in `MachineList.swift` at tag `1.4.1`. |
| `container-inspect-1.4.1.json` | Synthetic. Shape follows `ManagedContainer` / `ContainerConfiguration` at tag `1.4.1`, with the mounts, network, and `ssh = true` that `MachinesService.toContainerConfig` sets for a stock machine created with the default `--home-mount rw`. |

Identifiers are synthetic. Replace the synthetic files with captured output
(sanitized) once a qualified runtime is available (spec WP-0).
