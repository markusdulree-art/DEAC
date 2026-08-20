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


## Evidence graph / process identity layer (v4)

The service now reconstructs process instances rather than treating a PID as a permanent identity. A process instance is keyed by `(PID, creation-time token)`, with its observed image path retained for attribution. This prevents evidence from one process instance being correlated with a later process that reused the same PID.

Kernel events are normalized into a temporal evidence graph. The graph currently models:

- process creation/exit
- image-load observations
- dangerous and read-only handle observations
- executable private-memory observations
- queue-loss observations

Correlations are explicit and time-bounded. A suspicious module or executable private PE region can receive additional weight only when the graph can associate the observations with the same target process instance and, for handle correlations, the same source process instance. Ordinary module loads do not contribute a memory-correlation edge.

The service also detects kernel event sequence gaps and polls the driver for cumulative queue-drop counts. Telemetry loss is recorded as a data-quality/integrity event instead of being silently ignored. Driver status now exposes callback capability bits and queue-drop state.

The protocol version was bumped to **4** because `DriverStatus` gained the queue-drop field and the capability contract was expanded.

### Current evidence flow

```text
Kernel / user observations
        |
        v
Process identity + event normalization
        |
        v
Temporal evidence graph
        |
        +--> module provenance
        +--> handle attribution
        +--> memory-state evidence
        +--> telemetry-quality state
        |
        v
Policy evidence + correlation boost
        |
        v
Allow / Monitor / Review / Enforce
```

The graph is deliberately an evidence layer rather than a direct ban mechanism. Correlation strength is bounded, and loss of telemetry is represented explicitly so the policy layer can account for incomplete observation.


## v5 hardening pass

This iteration applies the next set of security-engineering fixes on top of the evidence graph:

- Process-instance identity is carried into policy evidence and session/audit records.
- Evidence fusion now requires independent evidence families for enforcement and treats graph relationships as contextual strength rather than simply adding a raw score.
- Correlation windows are event-specific instead of one global ten-second window.
- Memory-region deduplication is scoped to the CS2 process instance, region size, and protection state.
- Telemetry distinguishes received samples from valid samples and exposes coverage ratio.
- Module assessment records signer certificate thumbprints and a best-effort mapped-image path check; startup baselines contain only already-trusted game-root hashes, never arbitrary unsigned content.
- Audit/evidence records are structured JSONL rather than message-heavy/CSV records.
- Queue health distinguishes operational state from historical loss.
- Handle telemetry is filtered in-kernel to reduce background noise while retaining CS2-targeted and security-sensitive observations; pre-operation requested access is no longer represented as final granted access.
- Configuration uses JSON parsing and Windows atomic replacement semantics instead of regex extraction and delete-then-rename.
- Update protocol compatibility tracks `kProtocolVersion` rather than a stale constant.

The portable test target is intentionally built without Windows-only configuration code on non-Windows hosts; the Windows service target continues to include the full configuration implementation.
