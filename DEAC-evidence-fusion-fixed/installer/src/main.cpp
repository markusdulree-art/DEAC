#include "system_requirements.h"
#include "service_install.h"
#include <windows.h>
#include <iostream>

int wmain() {
    const auto req = deac::installer::CheckRequirements();
    std::wcout << L"DEAC system requirements\n"
               << L"  Secure Boot: " << (req.secure_boot ? L"ON" : L"OFF") << L"\n"
               << L"  HVCI:        " << (req.hvci ? L"ON" : L"OFF") << L"\n"
               << L"  VBS:         " << (req.vbs ? L"ON" : L"OFF") << L"\n";
    if (!req.meets_policy) {
        std::wcerr << L"System does not meet the configured DEAC security policy.\n";
        return 2;
    }
    std::wcout << L"Requirements satisfied. Deployment should be performed from an elevated installer package.\n";
    return 0;
}
