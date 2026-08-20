#pragma once
#include <cstdint>
#include <cstddef>

namespace deac::protocol {

inline constexpr std::uint32_t kProtocolVersion = 3;
inline constexpr std::uint32_t kMaxEventPayload = 512;

using ProcessId = std::uint64_t;
using ThreadId = std::uint64_t;

enum class EventType : std::uint32_t {
    None = 0,
    ProcessCreated = 1,
    ProcessExited = 2,
    ThreadCreated = 3,
    ThreadExited = 4,
    ImageLoaded = 5,
    ProtectedHandleAttempt = 6,
    Heartbeat = 7,
    PlatformState = 8,
    DriverState = 9,
    QueueOverflow = 10,
    MemoryAnomaly = 11,
};

enum class PlatformLevel : std::uint32_t {
    Unknown = 0,
    Degraded = 1,
    Baseline = 2,
    Hardened = 3,
};

struct PlatformSecurityState final {
    std::uint32_t size;
    std::uint32_t version;
    std::uint8_t secure_boot;
    std::uint8_t hvci_enabled;
    std::uint8_t vbs_enabled;
    std::uint8_t code_integrity_present;
    std::uint32_t level;
};

struct Event final {
    std::uint32_t size;
    std::uint32_t version;
    std::uint32_t type;
    std::uint32_t flags;
    std::uint64_t sequence;
    std::uint64_t timestamp_qpc;
    ProcessId pid;
    ThreadId tid;
    std::uint32_t payload_size;
    std::uint32_t reserved;
    std::uint8_t payload[kMaxEventPayload];
};

struct ProcessPayload final {
    std::uint64_t parent_pid;
    std::uint64_t create_time_100ns;
    std::uint8_t is_subsystem;
    std::uint8_t reserved[7];
};

struct ImagePayload final {
    std::uint64_t image_base;
    std::uint32_t image_size;
    std::uint32_t flags;
    wchar_t image_name[192];
};

struct HandlePayload final {
    std::uint64_t source_pid;
    std::uint32_t desired_access;
    std::uint32_t granted_access;
    std::uint32_t operation;
    std::uint32_t reserved;
};

struct PolicyFlags final {
    std::uint32_t size;
    std::uint32_t version;
    std::uint32_t flags;
    std::uint32_t reserved;
};

struct DriverStatus final {
    std::uint32_t size;
    std::uint32_t version;
    std::uint32_t state;
    std::uint32_t flags;
    std::uint64_t uptime_ms;
    PlatformSecurityState platform;
};

} // namespace deac::protocol

extern "C" {

#ifndef FILE_DEVICE_DEAC
#define FILE_DEVICE_DEAC 0x00008010
#endif

#define IOCTL_DEAC_GET_VERSION \
    CTL_CODE(FILE_DEVICE_DEAC, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_DEAC_GET_STATUS \
    CTL_CODE(FILE_DEVICE_DEAC, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_DEAC_GET_EVENT \
    CTL_CODE(FILE_DEVICE_DEAC, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_DEAC_SET_POLICY_FLAGS \
    CTL_CODE(FILE_DEVICE_DEAC, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)

}
