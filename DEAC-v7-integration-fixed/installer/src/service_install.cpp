#include "service_install.h"
#include <windows.h>

namespace deac::installer {

bool ServiceInstaller::installDriver(const std::filesystem::path& sysPath) const {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    SC_HANDLE svc = CreateServiceW(scm, L"DEAC", L"DEAC Kernel Driver", SERVICE_START | DELETE | SERVICE_QUERY_STATUS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, sysPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    const bool ok = svc || GetLastError() == ERROR_SERVICE_EXISTS;
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool ServiceInstaller::removeDriver() const {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"DEAC", DELETE);
    if (!svc) { CloseServiceHandle(scm); return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST; }
    SERVICE_STATUS ignored{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ignored);
    const bool ok = DeleteService(svc) != FALSE;
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
}

bool ServiceInstaller::installService(const std::filesystem::path& exePath) const {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    SC_HANDLE svc = CreateServiceW(scm, L"DEACService", L"DEAC User Mode Service", SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, exePath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    const bool ok = svc || GetLastError() == ERROR_SERVICE_EXISTS;
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

bool ServiceInstaller::removeService() const {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceW(scm, L"DEACService", DELETE);
    if (!svc) { CloseServiceHandle(scm); return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST; }
    SERVICE_STATUS ignored{};
    ControlService(svc, SERVICE_CONTROL_STOP, &ignored);
    const bool ok = DeleteService(svc) != FALSE;
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
}
}
