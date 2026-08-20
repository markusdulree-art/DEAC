#include "service_runtime.h"
#include <windows.h>
#include <atomic>

namespace {
deac::service::Runtime* g_runtime = nullptr;
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS g_status{};

void SetState(DWORD state, DWORD win32Exit = NO_ERROR, DWORD waitHint = 0) {
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32Exit;
    g_status.dwWaitHint = waitHint;
    SetServiceStatus(g_statusHandle, &g_status);
}

void WINAPI Handler(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        SetState(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_runtime) g_runtime->stop();
        SetState(SERVICE_STOPPED);
    }
}

void WINAPI ServiceMain(DWORD, LPSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerA("DEACService", Handler);
    if (!g_statusHandle) return;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetState(SERVICE_START_PENDING, NO_ERROR, 5000);

    deac::service::Runtime runtime;
    g_runtime = &runtime;
    if (!runtime.start()) {
        g_runtime = nullptr;
        SetState(SERVICE_STOPPED, ERROR_SERVICE_NOT_ACTIVE);
        return;
    }

    SetState(SERVICE_RUNNING);
    while (g_status.dwCurrentState == SERVICE_RUNNING) {
        Sleep(250);
    }

    runtime.stop();
    g_runtime = nullptr;
}
}

int main() {
    SERVICE_TABLE_ENTRYA table[] = {
        { const_cast<LPSTR>("DEACService"), ServiceMain },
        { nullptr, nullptr }
    };
    return StartServiceCtrlDispatcherA(table) ? 0 : static_cast<int>(GetLastError());
}
