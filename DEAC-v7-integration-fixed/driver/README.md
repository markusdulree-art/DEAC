# DEAC kernel driver

This directory contains a WDM/NT kernel-mode implementation intended to be built with the Windows Driver Kit (WDK) and Visual Studio's driver build tooling.

## Security posture

The driver is intentionally observation-first. It performs platform security posture checks, receives process/thread lifecycle notifications, provides a bounded event queue, and exposes a small IOCTL ABI to the service.

It does **not** attempt to bypass or conceal itself from Windows, VAC, or other security software.

## Build requirements

- Visual Studio with Windows Driver Kit integration
- Matching Windows SDK + WDK
- x64 target
- Driver must be signed through the normal Windows driver signing/deployment workflow appropriate for the target environment

## HVCI compatibility

All dynamic allocations use `ExAllocatePool2` with `POOL_FLAG_NON_PAGED` and the implementation does not create writable+executable memory or patch executable system memory.
