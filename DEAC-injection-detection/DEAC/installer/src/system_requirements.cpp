#include "system_requirements.h"
#include <wbemidl.h>
#pragma comment(lib, "advapi32.lib")

namespace {
bool ReadDword(HKEY root, const wchar_t* path, const wchar_t* value, DWORD& out) {
    HKEY key{};
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return false;
    DWORD type=0, bytes=sizeof(out);
    const auto rc = RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<LPBYTE>(&out), &bytes);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_DWORD;
}
}

namespace deac::installer {
Requirements CheckRequirements() {
    Requirements r{};
    DWORD value = 0;
    if (ReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled", value)) r.secure_boot = value != 0;
    value = 0;
    if (ReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled", value)) r.hvci = value != 0;
    value = 0;
    if (ReadDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity", value)) r.vbs = value != 0;
    // TPM presence is not used as a bypass gate; the installer reports it for diagnostics.
    r.meets_policy = r.secure_boot && r.hvci;
    return r;
}
}
