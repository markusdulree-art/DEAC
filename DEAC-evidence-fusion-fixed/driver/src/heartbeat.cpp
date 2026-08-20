#include <ntddk.h>
#include "deac_protocol.h"
#include "deac_driver.h"
#include "event_queue.h"

namespace {
HANDLE g_thread = nullptr;
KEVENT g_stop_event{};
volatile LONG g_running = 0;

VOID HeartbeatThread(_In_ PVOID) {
    LARGE_INTEGER interval{};
    interval.QuadPart = -10000000LL;
    while (InterlockedCompareExchange(&g_running, 0, 0) != 0) {
        deac::protocol::Event event{};
        event.size = sizeof(event);
        event.version = deac::protocol::kProtocolVersion;
        event.type = static_cast<std::uint32_t>(deac::protocol::EventType::Heartbeat);
        event.timestamp_qpc = KeQueryPerformanceCounter(nullptr).QuadPart;
        deac::kernel::g_event_queue.Push(event);

        if (KeWaitForSingleObject(&g_stop_event, Executive, KernelMode, FALSE, &interval) == STATUS_WAIT_0) {
            break;
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
}

NTSTATUS DeacStartHeartbeat() {
    KeInitializeEvent(&g_stop_event, NotificationEvent, FALSE);
    InterlockedExchange(&g_running, 1);
    return PsCreateSystemThread(&g_thread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, HeartbeatThread, nullptr);
}

VOID DeacStopHeartbeat() {
    if (!g_thread) return;
    InterlockedExchange(&g_running, 0);
    KeSetEvent(&g_stop_event, IO_NO_INCREMENT, FALSE);
    ZwWaitForSingleObject(g_thread, FALSE, nullptr);
    ZwClose(g_thread);
    g_thread = nullptr;
}
