# DEAC CS2 injection/tamper detection signals

DEAC uses independent observations rather than assuming that a DLL load event exists for every form of code injection.

## Signals

1. **Image-load inventory**
   - Kernel image-load callbacks provide normal mapped-image events.
   - The service verifies file identity, SHA-256, Authenticode signer, path and provenance.

2. **Process-handle observations**
   - Handle requests targeting CS2 are observed in the kernel.
   - VM write/operation, create-thread and duplicate-handle rights are high-value observations.
   - VM read is intentionally lower-weight because legitimate tools can request it.

3. **Executable private memory**
   - The service periodically enumerates CS2 memory regions with `VirtualQueryEx`.
   - `MEM_PRIVATE` executable regions are recorded as investigation signals.
   - A PE header found in a private executable region is stronger evidence because it is consistent with an in-memory/manual-mapped PE image.
   - Writable+executable private regions receive a higher score.
   - Only region metadata and the first page are sampled; DEAC does not dump arbitrary game memory.

4. **Correlation**
   - A private executable PE region appearing shortly after a dangerous CS2 handle observation receives substantially stronger evidence than either signal independently.
   - Module provenance and hash evidence are retained separately so the final policy can explain why a decision was reached.

## False-positive controls

- Official Windows/Valve/Steam/Microsoft signed modules are trusted.
- Signed third-party modules remain observable rather than automatically malicious.
- Baseline modules present when the CS2 inventory is established are not treated as new simply because they are unsigned.
- Memory findings are fed into the existing multi-event policy engine; the scanner does not itself ban.

This detector is defensive telemetry. It does not implement injection, concealment, or security-product evasion.
