#include <ntddk.h>
#include "deac_driver.h"
#include "deac_protocol.h"

namespace {

BOOLEAN ReadDwordValue(_In_ HANDLE key, _In_ PCUNICODE_STRING name, _Out_ PULONG value) {
    *value = 0;
    ULONG length = 0;
    NTSTATUS status = ZwQueryValueKey(key, name, KeyValuePartialInformation, nullptr, 0, &length);
    if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        return FALSE;
    }

    auto* info = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, length, 'DCAE'));
    if (!info) {
        return FALSE;
    }

    status = ZwQueryValueKey(key, name, KeyValuePartialInformation, info, length, &length);
    if (NT_SUCCESS(status) && info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) {
        RtlCopyMemory(value, info->Data, sizeof(ULONG));
    } else {
        status = STATUS_UNSUCCESSFUL;
    }

    ExFreePool(info);
    return NT_SUCCESS(status);
}

BOOLEAN ReadRegistryDword(_In_ PCUNICODE_STRING keyPath, _In_ PCUNICODE_STRING valueName, _Out_ PULONG value) {
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, const_cast<PUNICODE_STRING>(keyPath),
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    HANDLE key = nullptr;
    NTSTATUS status = ZwOpenKey(&key, KEY_QUERY_VALUE, &attributes);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    const BOOLEAN ok = ReadDwordValue(key, valueName, value);
    ZwClose(key);
    return ok;
}

BOOLEAN QuerySecureBoot() {
    // The SecureBoot state is exposed under this firmware variable namespace on UEFI systems.
    UNICODE_STRING variableName = RTL_CONSTANT_STRING(L"SecureBoot");
    GUID globalVariable = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } };
    UCHAR value = 0;
    ULONG size = sizeof(value);
    const NTSTATUS status = ExGetFirmwareEnvironmentVariable(&variableName, &globalVariable, &value, &size, nullptr);
    return NT_SUCCESS(status) && size == sizeof(value) && value == 1;
}

} // namespace

NTSTATUS DeacQueryPlatformSecurity(deac::protocol::PlatformSecurityState* outState) {
    if (!outState) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outState, sizeof(*outState));
    outState->size = sizeof(*outState);
    outState->version = 1;
    outState->secure_boot = QuerySecureBoot() ? 1 : 0;

    UNICODE_STRING hvciKey = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity");
    UNICODE_STRING enabled = RTL_CONSTANT_STRING(L"Enabled");
    ULONG hvci = 0;
    outState->hvci_enabled = ReadRegistryDword(&hvciKey, &enabled, &hvci) && hvci != 0 ? 1 : 0;

    UNICODE_STRING vbsKey = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard");
    UNICODE_STRING vbs = RTL_CONSTANT_STRING(L"EnableVirtualizationBasedSecurity");
    ULONG vbsValue = 0;
    outState->vbs_enabled = ReadRegistryDword(&vbsKey, &vbs, &vbsValue) && vbsValue != 0 ? 1 : 0;

    // We intentionally do not claim that a registry read proves every loaded module is signed.
    // The kernel driver itself is expected to be installed through the normal Windows code-integrity chain.
    outState->code_integrity_present = 1;

    const unsigned score =
        (outState->secure_boot ? 1u : 0u) +
        (outState->hvci_enabled ? 1u : 0u) +
        (outState->vbs_enabled ? 1u : 0u);

    if (score == 3) outState->level = static_cast<std::uint32_t>(deac::protocol::PlatformLevel::Hardened);
    else if (score >= 2) outState->level = static_cast<std::uint32_t>(deac::protocol::PlatformLevel::Baseline);
    else if (score >= 1) outState->level = static_cast<std::uint32_t>(deac::protocol::PlatformLevel::Degraded);
    else outState->level = static_cast<std::uint32_t>(deac::protocol::PlatformLevel::Unknown);

    return STATUS_SUCCESS;
}
