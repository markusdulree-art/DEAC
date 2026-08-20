#pragma once
#include <ntddk.h>
#include "deac_protocol.h"

namespace deac::kernel {

class EventQueue final {
public:
    static constexpr ULONG Capacity = 256;
    NTSTATUS Initialize();
    VOID Reset();
    BOOLEAN Push(const deac::protocol::Event& event);
    BOOLEAN Pop(deac::protocol::Event* out);
    PKEVENT Event();
    ULONG Dropped();

private:
    KSPIN_LOCK lock_{};
    KEVENT data_event_{};
    deac::protocol::Event ring_[Capacity]{};
    ULONG head_{0};
    ULONG tail_{0};
    ULONG count_{0};
    volatile LONG64 sequence_{0};
    volatile ULONG dropped_{0};
};

extern EventQueue g_event_queue;

} // namespace deac::kernel
