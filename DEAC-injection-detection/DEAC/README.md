# DEAC — Defensive Anti-Cheat Core

DEAC is a Windows anti-cheat architecture built around a signed kernel driver, a user-mode service, explicit telemetry inputs, and evidence-based policy decisions.

## Implemented

### Common
- Versioned kernel/user protocol.
- Fixed-size, ABI-stable event records.
- Driver status and policy flag IOCTL definitions.

### Kernel driver
- WDM driver initialization and deterministic unload.
- Secure-platform posture assessment for Secure Boot, VBS, and HVCI.
- Bounded kernel event queue with monotonic sequence numbers and drop accounting.
- Process creation/exit notifications.
- Non-system thread creation/exit notifications.
- Image-load notifications.
- Process handle-observation callbacks.
- Periodic kernel heartbeat.
- Status/version/event/policy IOCTLs.
- Partial-initialization cleanup paths.

### User-mode service
- Correct SCM lifecycle and cancellation-aware worker shutdown.
- Driver client with ABI/version validation.
- Telemetry rolling-window aggregation.
- Heuristic anomaly scoring with data-quality gating.
- Evidence store.
- Multi-event policy engine with monitor/review/enforce states.
- Windows CNG SHA-256 utility and stable pseudonym generation.
- Update manifest validation and SHA-256 artifact verification.
- Authenticode artifact verification support.
- Explicit game-state adapter boundary using JSON input; it does not inject into CS2 or provide arbitrary memory access.


### CS2 module integrity and provenance
- Tracks the actual `cs2.exe` process by executable identity rather than a hard-coded PID.
- Captures an initial module inventory and periodically reconciles it to recover from dropped/missed kernel events.
- Receives kernel image-load events and correlates them with user-mode file inventory.
- Computes SHA-256 for module files (bounded to prevent unbounded resource use).
- Verifies Authenticode signatures and records the signer subject when available.
- Explicitly trusts Windows-system modules and valid Valve/Steam/Microsoft signatures.
- Treats valid third-party signatures as observable rather than automatically malicious, avoiding false positives for legitimate overlays and utilities.
- Establishes a startup baseline for unsigned modules already present in the CS2 installation directory; new unsigned hashes appearing later are treated as suspicious evidence.
- Correlates suspicious module loads with recent dangerous process-handle observations.
- Keeps module provenance, signer, hash, and path in the audit trail.
- Module evidence is fed into the existing multi-event policy engine; a single module observation is not an automatic ban.


### Injection/tamper-oriented defensive signals
- Periodically inspects CS2 virtual-memory region metadata using `VirtualQueryEx`.
- Flags executable `MEM_PRIVATE` regions as an investigation signal rather than assuming every executable allocation is malicious.
- Samples only the first page of a suspicious region to identify a PE header; it does not dump arbitrary process memory.
- Gives a higher evidence weight to private executable PE regions and to writable+executable private regions.
- Correlates these findings with recent dangerous process-handle observations.
- Distinguishes stronger VM_WRITE/VM_OPERATION/CREATE_THREAD/DUP_HANDLE observations from lower-weight VM_READ observations to reduce false positives from legitimate tooling.
- Keeps the signal out of the automatic-ban path until it is combined with the configured multi-event policy.
- This is intended to catch an additional class of manual-map/in-memory module indicators that would not necessarily produce a normal image-load event.

### Installer
- Secure Boot/HVCI/VBS requirement detection.
- SCM helpers for driver/service installation and removal.
- Elevated deployment boundary kept separate from runtime detection.

### Tests
- Telemetry aggregation/detection tests.
- Multi-event policy tests.

## Security model

DEAC does not attempt to bypass, hide from, or disable VAC, Windows Code Integrity, HVCI, or other security products. The kernel driver is intended to operate through normal Windows driver installation and code-integrity mechanisms.

The driver is an observation and platform-integrity component. It is not a general-purpose game-memory reader or arbitrary kernel memory primitive.

Behavioral signals are evidence. A single model/heuristic score is not treated as an authoritative ban decision.

## Build validation

The portable detection/policy test target builds and passes with CMake/CTest on the development environment.

The kernel driver and Windows service/installer require a Windows + Visual Studio + WDK environment for final compilation, signing, installation, and runtime validation.

## Additional hardening in this iteration

- Runtime configuration loaded from `C:\ProgramData\DEAC\config.json` with strict bounds and safe defaults.
- Atomic config-file writes.
- Structured JSONL audit log at `C:\ProgramData\DEAC\audit.jsonl`.
- Policy configuration is applied at service startup instead of being compiled into the runtime.
- Decision transitions are audited separately from raw evidence.
- Driver device ACL is restricted to SYSTEM and local Administrators; ordinary desktop processes are not granted access by the device security descriptor.
- The portable test suite now covers configuration sanitization in addition to detection/policy behavior.

## Remaining deployment work

The production release pipeline still requires organization-specific signing certificates, the final Authenticode publisher policy, deployment packaging, and a signed update service/manifest infrastructure. Those are release secrets and deployment credentials, not source-code features.
