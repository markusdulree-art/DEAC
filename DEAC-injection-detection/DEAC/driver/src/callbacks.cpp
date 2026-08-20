#include <ntddk.h>
#include "deac_protocol.h"
#include "deac_driver.h"
#include "event_queue.h"

namespace deac::kernel { extern EventQueue g_event_queue; }

namespace {
PVOID g_ob_registration = nullptr;
BOOLEAN g_process_registered = FALSE;
BOOLEAN g_thread_registered = FALSE;
BOOLEAN g_image_registered = FALSE;

VOID FillBaseEvent(deac::protocol::Event* event, deac::protocol::EventType type, HANDLE pid, HANDLE tid) {
    RtlZeroMemory(event, sizeof(*event));
    event->size = sizeof(*event);
    event->version = deac::protocol::kProtocolVersion;
    event->type = static_cast<std::uint32_t>(type);
    event->pid = reinterpret_cast<ULONG_PTR>(pid);
    event->tid = reinterpret_cast<ULONG_PTR>(tid);
    event->timestamp_qpc = KeQueryPerformanceCounter(nullptr).QuadPart;
}

VOID ProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    deac::protocol::Event event{};
    FillBaseEvent(&event, CreateInfo ? deac::protocol::EventType::ProcessCreated
                                     : deac::protocol::EventType::ProcessExited,
                  ProcessId, nullptr);
    deac::protocol::ProcessPayload payload{};
    payload.parent_pid = reinterpret_cast<ULONG_PTR>(ParentId);
    if (CreateInfo) payload.is_subsystem = CreateInfo->IsSubsystemProcess ? 1 : 0;
    event.payload_size = sizeof(payload);
    RtlCopyMemory(event.payload, &payload, sizeof(payload));
    (void)deac::kernel::g_event_queue.Push(event);
}

VOID ThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create) {
    deac::protocol::Event event{};
    FillBaseEvent(&event, Create ? deac::protocol::EventType::ThreadCreated
                                 : deac::protocol::EventType::ThreadExited,
                  ProcessId, ThreadId);
    (void)deac::kernel::g_event_queue.Push(event);
}

VOID ImageNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo) {
    if (!ImageInfo) return;
    deac::protocol::Event event{};
    FillBaseEvent(&event, deac::protocol::EventType::ImageLoaded, ProcessId, nullptr);
    deac::protocol::ImagePayload payload{};
    payload.image_base = reinterpret_cast<ULONG_PTR>(ImageInfo->ImageBase);
    payload.image_size = ImageInfo->ImageSize;
    payload.flags = ImageInfo->SystemModeImage ? 1u : 0u;
    if (FullImageName && FullImageName->Buffer && FullImageName->Length) {
        const USHORT maxBytes = static_cast<USHORT>(sizeof(payload.image_name) - sizeof(wchar_t));
        const USHORT bytes = static_cast<USHORT>(FullImageName->Length < maxBytes ? FullImageName->Length : maxBytes);
        RtlCopyMemory(payload.image_name, FullImageName->Buffer, bytes);
        payload.image_name[bytes / sizeof(wchar_t)] = L'\0';
    }
    event.payload_size = sizeof(payload);
    RtlCopyMemory(event.payload, &payload, sizeof(payload));
    (void)deac::kernel::g_event_queue.Push(event);
}

OB_PREOP_CALLBACK_STATUS ObPreOperation(_In_ PVOID, _Inout_ POB_PRE_OPERATION_INFORMATION information) {
    if (!information || information->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;
    if (information->Operation == OB_OPERATION_HANDLE_CREATE || information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        deac::protocol::Event event{};
        const auto target = PsGetProcessId(reinterpret_cast<PEPROCESS>(information->Object));
        FillBaseEvent(&event, deac::protocol::EventType::ProtectedHandleAttempt, target, nullptr);
        deac::protocol::HandlePayload payload{};
        payload.source_pid = reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId());
        payload.operation = information->Operation;
        if (information->Operation == OB_OPERATION_HANDLE_CREATE) {
            payload.desired_access = information->Parameters->CreateHandleInformation.DesiredAccess;
            payload.granted_access = information->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        } else {
            payload.desired_access = information->Parameters->DuplicateHandleInformation.DesiredAccess;
            payload.granted_access = information->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        }
        event.payload_size = sizeof(payload);
        RtlCopyMemory(event.payload, &payload, sizeof(payload));
        (void)deac::kernel::g_event_queue.Push(event);
    }
    return OB_PREOP_SUCCESS;
}
}

NTSTATUS DeacRegisterCallbacks() {
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems, reinterpret_cast<PVOID>(ProcessNotify), FALSE);
    if (!NT_SUCCESS(status)) return status;
    g_process_registered = TRUE;

    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, reinterpret_cast<PVOID>(ThreadNotify));
    if (!NT_SUCCESS(status)) { DeacUnregisterCallbacks(); return status; }
    g_thread_registered = TRUE;

    status = PsSetLoadImageNotifyRoutine(ImageNotify);
    if (!NT_SUCCESS(status)) { DeacUnregisterCallbacks(); return status; }
    g_image_registered = TRUE;

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370720");
    OB_OPERATION_REGISTRATION operation{};
    operation.ObjectType = PsProcessType;
    operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation.PreOperation = ObPreOperation;

    OB_CALLBACK_REGISTRATION registration{};
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.RegistrationContext = nullptr;
    registration.Altitude = altitude;
    registration.OperationRegistration = &operation;

    status = ObRegisterCallbacks(&registration, &g_ob_registration);
    if (!NT_SUCCESS(status)) {
        g_ob_registration = nullptr;
        // Observation is optional; retain the process/thread/image event stream.
    }
    return STATUS_SUCCESS;
}

VOID DeacUnregisterCallbacks() {
    if (g_ob_registration) {
        ObUnRegisterCallbacks(g_ob_registration);
        g_ob_registration = nullptr;
    }
    if (g_image_registered) {
        PsRemoveLoadImageNotifyRoutine(ImageNotify);
        g_image_registered = FALSE;
    }
    if (g_thread_registered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
        g_thread_registered = FALSE;
    }
    if (g_process_registered) {
        PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems, reinterpret_cast<PVOID>(ProcessNotify), TRUE);
        g_process_registered = FALSE;
    }
}
