#pragma once

#include <ntddk.h>
#include "deac_protocol.h"

NTSTATUS DeacInitializeDevice(PDRIVER_OBJECT driverObject);
VOID DeacDeleteDevice(PDRIVER_OBJECT driverObject);
NTSTATUS DeacRegisterCallbacks();
VOID DeacUnregisterCallbacks();
NTSTATUS DeacStartHeartbeat();
VOID DeacStopHeartbeat();
NTSTATUS DeacQueryPlatformSecurity(deac::protocol::PlatformSecurityState* outState);
ULONG DeacCallbackCapabilityFlags();
