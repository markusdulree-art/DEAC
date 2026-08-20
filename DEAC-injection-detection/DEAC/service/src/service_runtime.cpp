#include "service_runtime.h"
#include "driver_client.h"
#include "deac_detection.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <unordered_map>
#include <Windows.h>

namespace {
std::uint64_t QpcToMs(std::uint64_t qpc, std::int64_t frequency) {
    if (frequency <= 0) return 0;
    const auto f = static_cast<std::uint64_t>(frequency);
    const auto whole = qpc / f;
    const auto rem = qpc % f;
    return whole * 1000ULL + (rem * 1000ULL) / f;
}

std::filesystem::path ProgramDataRoot() {
    wchar_t buffer[MAX_PATH]{};
    const DWORD length = GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
    if (length != 0 && length < MAX_PATH) return std::filesystem::path(buffer) / L"DEAC";
    return std::filesystem::path(L"C:\\ProgramData\\DEAC");
}

std::wstring ProcessImagePath(std::uint64_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) return {};
    wchar_t buffer[32768]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    const bool ok = QueryFullProcessImageNameW(process, 0, buffer, &size) != FALSE;
    CloseHandle(process);
    return ok ? std::wstring(buffer, size) : std::wstring{};
}

bool IsCs2(std::uint64_t pid) {
    const auto path = ProcessImagePath(pid);
    if (path.empty()) return false;
    const auto name = std::filesystem::path(path).filename().wstring();
    return _wcsicmp(name.c_str(), L"cs2.exe") == 0;
}

const char* ModuleVerdictName(deac::modules::Verdict verdict) {
    return deac::modules::ToString(verdict);
}
} // namespace

namespace deac::service {

Runtime::Runtime()
    : settings_(config::Defaults()),
      policy_engine_(policy::Config{}),
      evidence_(ProgramDataRoot() / L"evidence.csv"),
      audit_(ProgramDataRoot() / L"audit.jsonl") {}

Runtime::~Runtime() { stop(); }

bool Runtime::start() {
    if (events_.joinable() || telemetry_.joinable() || decisions_.joinable()) return false;
    stopping_.store(false, std::memory_order_release);

    const auto root = ProgramDataRoot();
    settings_ = config::Load(root / L"config.json");

    policy_engine_.configure(policy::Config{
        settings_.monitor_threshold,
        settings_.review_threshold,
        settings_.enforce_threshold,
        settings_.minimum_supporting_events,
        256
    });

    DriverClient probe;
    if (!probe.connect()) {
        audit_.write("driver", "driver unavailable");
        std::cerr << "DEAC: driver unavailable\n";
        return false;
    }

    if (const auto status = probe.status()) {
        std::cout << "DEAC: platform level=" << status->platform.level
                  << " secure_boot=" << static_cast<int>(status->platform.secure_boot)
                  << " vbs=" << static_cast<int>(status->platform.vbs_enabled)
                  << " hvci=" << static_cast<int>(status->platform.hvci_enabled) << '\n';
        audit_.write("platform", status->platform.level >= static_cast<std::uint32_t>(protocol::PlatformLevel::Baseline)
            ? "baseline-or-better" : "degraded");
    } else {
        audit_.write("driver", "status query failed");
    }

    events_ = std::thread(&Runtime::eventLoop, this);
    telemetry_ = std::thread(&Runtime::telemetryLoop, this);
    decisions_ = std::thread(&Runtime::decisionLoop, this);
    audit_.write("service", "runtime started");
    return true;
}

void Runtime::stop() noexcept {
    stopping_.store(true, std::memory_order_release);
    if (events_.joinable()) events_.join();
    if (telemetry_.joinable()) telemetry_.join();
    if (decisions_.joinable()) decisions_.join();
    audit_.write("service", "runtime stopped");
}

void Runtime::eventLoop() {
    DriverClient driver;
    if (!driver.connect()) {
        audit_.write("driver", "event loop connection failed");
        return;
    }

    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    std::unordered_map<std::uint64_t, std::uint64_t> recent_handle_sources;
    std::uint64_t last_inventory_refresh_ms = 0;
    std::uint64_t last_memory_scan_ms = 0;
    std::unordered_map<std::uintptr_t, std::uint64_t> recent_private_pe_regions;

    while (!stopping_.load(std::memory_order_acquire)) {
        const auto event = driver.nextEvent();
        if (!event) {
            std::this_thread::sleep_for(std::chrono::milliseconds(settings_.telemetry_poll_ms));
            continue;
        }

        const auto now_ms = GetTickCount64();
        const auto tracked_cs2 = cs2_pid_.load(std::memory_order_acquire);
        if (tracked_cs2 != 0 && (last_inventory_refresh_ms == 0 || now_ms - last_inventory_refresh_ms >= 10000)) {
            const auto snapshot = module_inventory_.Refresh(tracked_cs2);
            last_inventory_refresh_ms = now_ms;
            for (const auto& module : snapshot) {
                if (module.verdict == modules::Verdict::Suspicious) {
                    audit_.write("module", std::string("periodic inventory suspicious provenance=") +
                        modules::ToString(module.provenance) + " path=" + module.path.string() +
                        " sha256=" + module.sha256);
                }
            }
        }
        if (tracked_cs2 != 0 && (last_memory_scan_ms == 0 || now_ms - last_memory_scan_ms >= 2000)) {
            last_memory_scan_ms = now_ms;
            const auto regions = module_inventory_.ScanExecutablePrivateRegions(tracked_cs2);
            for (const auto& region : regions) {
                if (!region.pe_header && !region.writable) continue;
                const bool fresh = recent_private_pe_regions.emplace(region.base, now_ms).second;
                if (!fresh) continue;

                policy::Evidence memory_evidence{};
                memory_evidence.timestamp_ms = now_ms;
                memory_evidence.event_type = static_cast<std::uint32_t>(protocol::EventType::MemoryAnomaly);
                memory_evidence.pid = tracked_cs2;
                memory_evidence.anomaly = region.anomaly;
                memory_evidence.data_quality = region.pe_header ? 0.94f : 0.55f;

                bool correlated = false;
                for (auto it = recent_handle_sources.begin(); it != recent_handle_sources.end();) {
                    if (now_ms > it->second && now_ms - it->second > 5000) {
                        it = recent_handle_sources.erase(it);
                        continue;
                    }
                    correlated = true;
                    ++it;
                }
                if (correlated && region.pe_header) {
                    memory_evidence.anomaly = 0.995f;
                    memory_evidence.data_quality = 0.99f;
                    audit_.write("correlation", "private executable PE region correlated with recent dangerous CS2 handle observation");
                } else {
                    audit_.write("memory", std::string("suspicious executable private region reason=") +
                        (region.reason ? region.reason : "unknown") +
                        " base=0x" + std::to_string(region.base));
                }
                policy_engine_.add(memory_evidence);
                (void)evidence_.append(memory_evidence);
            }
            // Keep the correlation cache bounded.
            for (auto it = recent_private_pe_regions.begin(); it != recent_private_pe_regions.end();) {
                if (now_ms > it->second && now_ms - it->second > 30000) it = recent_private_pe_regions.erase(it);
                else ++it;
            }
        }

        const auto type = static_cast<protocol::EventType>(event->type);

        // Track the actual CS2 process. We do not assume that PID 1 or a hard-coded
        // process ID represents the game; process identity is established from its image.
        if (type == protocol::EventType::ProcessCreated && IsCs2(event->pid)) {
            cs2_pid_.store(event->pid, std::memory_order_release);
            const auto snapshot = module_inventory_.Refresh(event->pid);
            audit_.write("cs2", "process discovered; initial module inventory captured");
            for (const auto& module : snapshot) {
                if (module.verdict != modules::Verdict::Trusted) {
                    audit_.write("module", std::string("initial module ") + ModuleVerdictName(module.verdict) +
                        " provenance=" + modules::ToString(module.provenance) +
                        " path=" + module.path.string() +
                        " sha256=" + module.sha256);
                }
            }
        } else if (type == protocol::EventType::ProcessExited &&
                   event->pid == cs2_pid_.load(std::memory_order_acquire)) {
            cs2_pid_.store(0, std::memory_order_release);
            audit_.write("cs2", "process exited; module inventory retained for evidence");
        }

        policy::Evidence evidence{};
        evidence.timestamp_ms = QpcToMs(event->timestamp_qpc, frequency.QuadPart);
        evidence.sequence = event->sequence;
        evidence.event_type = event->type;
        evidence.pid = event->pid;
        evidence.tid = event->tid;

        if (type == protocol::EventType::QueueOverflow) {
            evidence.data_quality = 0.0f;
            evidence.anomaly = 0.0f;
            audit_.write("event", "kernel queue overflow reported");
        } else if (type == protocol::EventType::Heartbeat || type == protocol::EventType::PlatformState) {
            evidence.data_quality = 0.0f;
        } else if (type == protocol::EventType::ProtectedHandleAttempt &&
                   event->pid == cs2_pid_.load(std::memory_order_acquire) &&
                   event->payload_size >= sizeof(protocol::HandlePayload)) {
            const auto* payload = reinterpret_cast<const protocol::HandlePayload*>(event->payload);
            const auto access = payload->desired_access;
            const bool dangerous = (access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                              PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) != 0;
            const bool memory_read = (access & PROCESS_VM_READ) != 0;
            if (dangerous) {
                recent_handle_sources[payload->source_pid] = now_ms;
                evidence.data_quality = 0.35f;
                evidence.anomaly = 0.25f;
                audit_.write("handle", "CS2 dangerous handle observation source=" + std::to_string(payload->source_pid));
            } else if (memory_read) {
                // VM_READ is intentionally a low-weight observation because legitimate
                // diagnostics, capture tools and overlays can request it.
                evidence.data_quality = 0.12f;
                evidence.anomaly = 0.08f;
                audit_.write("handle", "CS2 read-handle observation source=" + std::to_string(payload->source_pid));
            } else {
                evidence.data_quality = 0.05f;
                evidence.anomaly = 0.0f;
            }
        } else if (type == protocol::EventType::ImageLoaded &&
                   event->pid == cs2_pid_.load(std::memory_order_acquire)) {
            const auto module = module_inventory_.ObserveImageLoad(*event);
            if (module.verdict == modules::Verdict::Suspicious) {
                evidence.data_quality = 0.90f;
                evidence.anomaly = module.anomaly;
                audit_.write("module", std::string("suspicious load provenance=") +
                    modules::ToString(module.provenance) + " path=" + module.path.string() +
                    " sha256=" + module.sha256 + " publisher=" + module.publisher);

                // Correlate a suspicious module load with a recent dangerous handle open.
                // This is intentionally stronger than either observation alone.
                bool correlated = false;
                for (auto it = recent_handle_sources.begin(); it != recent_handle_sources.end();) {
                    if (now_ms > it->second && now_ms - it->second > 5000) {
                        it = recent_handle_sources.erase(it);
                        continue;
                    }
                    correlated = true;
                    ++it;
                }
                if (correlated) {
                    evidence.anomaly = std::max(evidence.anomaly, 0.98f);
                    evidence.data_quality = 0.98f;
                    audit_.write("correlation", "suspicious CS2 module load correlated with recent dangerous handle observation");
                }
            } else {
                // Official Valve/Microsoft/Steam modules are explicitly treated as trusted;
                // signed third-party modules remain observable but do not become cheat evidence.
                evidence.data_quality = 0.0f;
                evidence.anomaly = 0.0f;
            }
        } else if (type == protocol::EventType::ThreadCreated || type == protocol::EventType::ThreadExited ||
                   type == protocol::EventType::ProcessCreated || type == protocol::EventType::ProcessExited) {
            evidence.data_quality = 0.05f;
            evidence.anomaly = 0.0f;
        }

        if (evidence.data_quality > 0.0f) {
            policy_engine_.add(evidence);
            (void)evidence_.append(evidence);
        }
    }
}

void Runtime::telemetryLoop() {
    while (!stopping_.load(std::memory_order_acquire)) {
        const auto aggregate = telemetry_engine_.aggregate();
        if (aggregate.sample_count >= 20) {
            const auto score = detection::Evaluate(aggregate);
            policy::Evidence evidence{};
            evidence.timestamp_ms = GetTickCount64();
            evidence.anomaly = score.anomaly;
            evidence.data_quality = score.data_quality;
            evidence.event_type = static_cast<std::uint32_t>(protocol::EventType::DriverState);
            policy_engine_.add(evidence);
            (void)evidence_.append(evidence);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(settings_.telemetry_poll_ms));
    }
}

void Runtime::decisionLoop() {
    policy::Decision previous = policy::Decision::Allow;
    while (!stopping_.load(std::memory_order_acquire)) {
        const auto result = policy_engine_.evaluate();
        if (result.decision != previous) {
            const char* name = "Allow";
            switch (result.decision) {
                case policy::Decision::Monitor: name = "Monitor"; break;
                case policy::Decision::Review: name = "Review"; break;
                case policy::Decision::Enforce: name = "Enforce"; break;
                default: break;
            }
            audit_.write("decision", name);
            previous = result.decision;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

} // namespace deac::service
