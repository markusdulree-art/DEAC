# DEAC protocol contract

The kernel/service boundary is a versioned IOCTL ABI.

## Rules

1. Every structure starts with `size` and `version` where appropriate.
2. Unknown IOCTLs are rejected.
3. User-mode never supplies kernel pointers.
4. Kernel events are bounded to 256 records and carry monotonically increasing sequence numbers.
5. Event payloads are fixed-size and length-delimited.
6. The kernel never accepts arbitrary code, function pointers, executable buffers, or memory-copy requests from the service.
7. Game-specific telemetry is not part of the kernel ABI.

This boundary is designed to reduce the blast radius of a compromised or buggy user-mode component.


## Protocol v4 changes (historical)

`kProtocolVersion` is now 5. `DriverStatus` includes `queue_dropped`, and `flags` exposes callback/queue capability bits from `DriverCapability`. Consumers must reject mismatched versions rather than guessing the layout.


## Protocol v5 notes

`DriverCapability` now separates `QueueOperational` from `QueueLossDetected`. `HandlePayload::granted_access` is zero during pre-operation telemetry because the callback observes requested access before the final handle grant decision; DEAC does not claim post-operation grant state from that event.


## v5 evidence semantics

DEAC treats process identity, telemetry completeness, and event relationships as separate signals.
A shared target/source process does not by itself create a causal correlation edge. Relationship-specific
time windows are used for handle→module, handle→memory, and module→memory relationships.

`DriverCapability::QueueOperational` describes current ability to service the event queue.
`DriverCapability::QueueLossDetected` is historical/cumulative loss state; the service also tracks the
reported drop counter so a single old drop is not misinterpreted as permanent operational failure.

Telemetry aggregates distinguish `received_count`, `valid_count`, and `invalid_count`. Only valid samples
contribute to feature statistics. Policy fusion uses evidence families with diminishing returns for repeated
observations from the same family; correlation is contextual reinforcement rather than an independent family.

Signed modules are not implicitly trusted from a display-name publisher string. Production trust policy should
configure cryptographic signer thumbprints explicitly via `trusted_signer_thumbprints`; otherwise a valid but
unlisted signature remains observable rather than authoritative trust.
