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
