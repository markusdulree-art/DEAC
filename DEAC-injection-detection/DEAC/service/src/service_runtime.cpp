#include "service_runtime.h"
#include "driver_client.h"
#include "deac_detection.h"
#include "evidence_graph.h"
#include "process_identity.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
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

const char* DecisionName(deac::policy::Decision decision) {
    switch (decision) {
        case deac::policy::Decision::Monitor: return "Monitor";
        case deac::policy::Decision::Review: return "Review";
        case deac::policy::Decision::Enforce: return "Enforce";
        default: return "Allow";
    }
}

deac::graph::EventKind ToGraphKind(deac::protocol::EventType type) {
    using deac::graph::EventKind;
    using deac::protocol::EventType;
    switch (type) {
        case EventType::ProcessCreated: return EventKind::ProcessCreated;
        case EventType::ProcessExited: return EventKind::ProcessExited;
        case EventType::ImageLoaded: return EventKind::ImageLoaded;
        case EventType::ProtectedHandleAttempt: return EventKind::DangerousHandle;
        case EventType::MemoryAnomaly: return EventKind::MemoryPrivateExecutable;
        case EventType::QueueOverflow: return EventKind::QueueOverflow;
        default: return EventKind::Unknown;
    }
}
} // namespace

namespace deac::service {

Runtime::Runtime()
    : settings_(config::Defaults()),
      policy_engine_(policy::Config{}),
      evidence_(ProgramDataRoot() / L"evidence.jsonl"),
      audit_(ProgramDataRoot() / L"audit.jsonl"),
      graph_(10'000, 4096) {}

Runtime::~Runtime() { stop(); }

bool Runtime::start() {
    if (events_.joinable() || telemetry_.joinable() || decisions_.joinable()) return false;
    stopping_.store(false, std::memory_order_release);

    const auto root = ProgramDataRoot();
    settings_ = config::Load(root / L"config.json");
    module_inventory_.SetTrustedSignerThumbprints(settings_.trusted_signer_thumbprints);

    policy_engine_.configure(policy::Config{
        settings_.monitor_threshold,
        settings_.review_threshold,
        settings_.enforce_threshold,
        settings_.minimum_supporting_events,
        settings_.minimum_supporting_families,
        256
    });

    DriverClient probe;
    if (!probe.connect()) {
        audit_.write("driver", "driver unavailable");
        std::cerr << "DEAC: driver unavailable\n";
        return false;
    }

    if (const auto status = probe.status()) {
        driver_flags_.store(status->flags, std::memory_order_release);
        driver_dropped_.store(status->queue_dropped, std::memory_order_release);
        std::cout << "DEAC: platform level=" << status->platform.level
                  << " secure_boot=" << static_cast<int>(status->platform.secure_boot)
                  << " vbs=" << static_cast<int>(status->platform.vbs_enabled)
                  << " hvci=" << static_cast<int>(status->platform.hvci_enabled)
                  << " capabilities=0x" << std::hex << status->flags
                  << " dropped=" << std::dec << status->queue_dropped << '\n';
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
    std::uint64_t last_inventory_refresh_ms = 0;
    std::uint64_t last_memory_scan_ms = 0;
    std::uint64_t last_status_poll_ms = 0;
    std::uint64_t last_sequence = 0;
    std::uint64_t last_dropped = driver_dropped_.load(std::memory_order_acquire);
    std::unordered_map<std::string, std::uint64_t> recent_private_regions;

    while (!stopping_.load(std::memory_order_acquire)) {
        const auto event = driver.nextEvent();
        const auto now_ms = GetTickCount64();

        if (now_ms - last_status_poll_ms >= 2000) {
            last_status_poll_ms = now_ms;
            if (const auto status = driver.status()) {
                driver_flags_.store(status->flags, std::memory_order_release);
                if (status->queue_dropped > last_dropped) {
                    policy::Evidence loss{};
                    loss.timestamp_ms = now_ms;
                    loss.event_type = static_cast<std::uint32_t>(protocol::EventType::QueueOverflow);
                    loss.anomaly = 0.0f;
                    loss.data_quality = 0.0f;
                    loss.evidence_key = "telemetry_loss";
                    loss.evidence_family = "telemetry-integrity";
                    policy_engine_.add(loss);
                    (void)evidence_.append(loss);
                    audit::Record rec{};
                    rec.category = "telemetry";
                    rec.message = "kernel event queue loss detected; telemetry integrity degraded";
                    rec.monotonic_ms = now_ms;
                    rec.evidence_key = loss.evidence_key;
                    rec.session_id = cs2_identity_.Key();
                    audit_.write(rec);
                    last_dropped = status->queue_dropped;
                }
            }
        }

        const auto tracked_pid = cs2_pid_.load(std::memory_order_acquire);
        if (tracked_pid != 0 && now_ms - last_inventory_refresh_ms >= 10000) {
            const auto snapshot = module_inventory_.Refresh(tracked_pid);
            last_inventory_refresh_ms = now_ms;
            for (const auto& module : snapshot) {
                if (module.verdict == modules::Verdict::Suspicious) {
                    audit_.write("module", std::string("periodic inventory suspicious provenance=") +
                        modules::ToString(module.provenance) + " path=" + module.path.string() +
                        " sha256=" + module.sha256);
                }
            }
        }

        if (tracked_pid != 0 && now_ms - last_memory_scan_ms >= 2000) {
            last_memory_scan_ms = now_ms;
            identity::ProcessIdentity target{};
            if (!identity_tracker_.get(tracked_pid, target)) target = identity_tracker_.observe(tracked_pid);
            const auto regions = module_inventory_.ScanExecutablePrivateRegions(tracked_pid);
            for (const auto& region : regions) {
                if (!region.pe_header && !region.writable) continue;
                region.birth_token = target.birth_token;
                const std::string region_key = target.Key() + ":" + std::to_string(region.base) + ":" +
                    std::to_string(region.region_size) + ":" + std::to_string(region.protection);
                if (!recent_private_regions.emplace(region_key, now_ms).second) continue;

                const auto kind = region.pe_header ? graph::EventKind::MemoryPrivateExecutablePe
                                                   : graph::EventKind::MemoryPrivateExecutable;
                graph_.observe(graph::Event{now_ms, 0, kind, target, {},
                                            std::to_string(region.base), region.anomaly,
                                            region.pe_header ? 0.94f : 0.55f});

                policy::Evidence memory{};
                memory.timestamp_ms = now_ms;
                memory.event_type = static_cast<std::uint32_t>(protocol::EventType::MemoryAnomaly);
                memory.pid = tracked_pid;
                memory.target = target;
                memory.anomaly = region.anomaly;
                memory.data_quality = region.pe_header ? 0.94f : 0.55f;
                memory.evidence_key = region.pe_header ? "private_pe" : "private_executable";
                memory.evidence_family = "memory-integrity";
                memory.correlation_id = target.Key() + ":" + region_key;

                const auto sources = graph_.recent_sources(target, graph::EventKind::DangerousHandle, now_ms);
                for (const auto& source : sources) {
                    const auto corr = graph_.correlate(source, target, kind, now_ms);
                    if (corr.handle_before_memory) {
                        memory.source_pid = source.pid;
                        memory.source_birth_token = source.birth_token;
                        memory.source = source;
                        memory.correlation_edges = corr.supporting_edges;
                        memory.correlation_boost = corr.boost;
                        memory.anomaly = std::max(memory.anomaly, 0.995f);
                        memory.data_quality = std::max(memory.data_quality, 0.99f);
                        audit_.write("correlation", "same-process-instance dangerous handle precedes executable private memory");
                        break;
                    }
                }

                policy_engine_.add(memory);
                (void)evidence_.append(memory);
            }
            for (auto it = recent_private_regions.begin(); it != recent_private_regions.end();) {
                if (now_ms > it->second && now_ms - it->second > 30000) it = recent_private_regions.erase(it);
                else ++it;
            }
        }

        if (!event) {
            std::this_thread::sleep_for(std::chrono::milliseconds(settings_.telemetry_poll_ms));
            continue;
        }

        if (last_sequence != 0 && event->sequence > last_sequence + 1) {
            policy::Evidence gap{};
            gap.timestamp_ms = QpcToMs(event->timestamp_qpc, frequency.QuadPart);
            gap.sequence = event->sequence;
            gap.event_type = static_cast<std::uint32_t>(protocol::EventType::QueueOverflow);
            gap.anomaly = 0.0f;
            gap.data_quality = 0.0f;
            gap.evidence_key = "sequence_gap";
            gap.evidence_family = "telemetry-integrity";
            policy_engine_.add(gap);
            (void)evidence_.append(gap);
            audit_.write("telemetry", "kernel event sequence gap detected");
        }
        last_sequence = event->sequence;

        const auto type = static_cast<protocol::EventType>(event->type);
        identity::ProcessIdentity target{};
        if (type == protocol::EventType::ProcessExited) {
            identity_tracker_.get(event->pid, target);
        } else {
            target = identity_tracker_.observe(event->pid);
        }

        if (type == protocol::EventType::ProcessCreated && IsCs2(event->pid)) {
            cs2_pid_.store(event->pid, std::memory_order_release);
            cs2_identity_ = identity_tracker_.observe(event->pid);
            module_inventory_.AttachToProcess(event->pid);
            const auto snapshot = module_inventory_.Refresh(event->pid);
            audit::Record session_rec{};
            session_rec.category = "cs2";
            session_rec.message = "process discovered; stable process identity established";
            session_rec.monotonic_ms = now_ms;
            session_rec.sequence = event->sequence;
            session_rec.event_type = event->type;
            session_rec.session_id = cs2_identity_.Key();
            session_rec.target = cs2_identity_;
            audit_.write(session_rec);
            for (const auto& module : snapshot) {
                graph_.observe(graph::Event{now_ms, event->sequence, graph::EventKind::ImageLoaded,
                                            cs2_identity_, {}, module.sha256, module.anomaly,
                                            module.verdict == modules::Verdict::Suspicious ? 0.9f : 0.0f});
                if (module.verdict != modules::Verdict::Trusted) {
                    audit_.write("module", std::string("initial module ") + modules::ToString(module.verdict) +
                        " provenance=" + modules::ToString(module.provenance) +
                        " path=" + module.path.string() + " sha256=" + module.sha256);
                }
            }
        }

        if (type == protocol::EventType::ProcessExited && event->pid == cs2_pid_.load(std::memory_order_acquire)) {
            graph_.observe(graph::Event{now_ms, event->sequence, graph::EventKind::ProcessExited,
                                        cs2_identity_, {}, {}, 0.0f, 1.0f});
            cs2_pid_.store(0, std::memory_order_release);
            identity_tracker_.remove(event->pid);
            audit::Record session_rec{};
            session_rec.category = "cs2";
            session_rec.message = "process exited; evidence graph retained for current session";
            session_rec.monotonic_ms = now_ms;
            session_rec.sequence = event->sequence;
            session_rec.event_type = event->type;
            session_rec.session_id = cs2_identity_.Key();
            session_rec.target = cs2_identity_;
            audit_.write(session_rec);
            continue;
        }

        if (target.valid()) {
            const auto kind = ToGraphKind(type);
            identity::ProcessIdentity source{};
            if (type == protocol::EventType::ProtectedHandleAttempt && event->payload_size >= sizeof(protocol::HandlePayload)) {
                const auto* payload = reinterpret_cast<const protocol::HandlePayload*>(event->payload);
                source = identity_tracker_.observe(payload->source_pid);
                const auto access = payload->desired_access;
                const bool dangerous = (access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                                  PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) != 0;
                const bool read = (access & PROCESS_VM_READ) != 0;
                if (event->pid == cs2_pid_.load(std::memory_order_acquire)) {
                    graph_.observe(graph::Event{now_ms, event->sequence,
                                                dangerous ? graph::EventKind::DangerousHandle : graph::EventKind::ReadHandle,
                                                target, source, {}, dangerous ? 0.25f : 0.08f,
                                                dangerous ? 0.35f : 0.12f});
                }
            } else if (type == protocol::EventType::ImageLoaded && event->pid == cs2_pid_.load(std::memory_order_acquire)) {
                const auto module = module_inventory_.ObserveImageLoad(*event);
                graph_.observe(graph::Event{now_ms, event->sequence, graph::EventKind::ImageLoaded,
                                            target, {}, module.sha256, module.anomaly,
                                            module.verdict == modules::Verdict::Suspicious ? 0.90f : 0.0f});
            } else if (type == protocol::EventType::ProcessCreated) {
                graph_.observe(graph::Event{now_ms, event->sequence, kind, target, {}, {}, 0.0f, 0.05f});
            }
        }

        policy::Evidence evidence{};
        evidence.timestamp_ms = QpcToMs(event->timestamp_qpc, frequency.QuadPart);
        evidence.sequence = event->sequence;
        evidence.event_type = event->type;
        evidence.pid = event->pid;
        evidence.tid = event->tid;

        if (type == protocol::EventType::ProtectedHandleAttempt &&
            event->pid == cs2_pid_.load(std::memory_order_acquire) &&
            event->payload_size >= sizeof(protocol::HandlePayload)) {
            const auto* payload = reinterpret_cast<const protocol::HandlePayload*>(event->payload);
            const auto access = payload->desired_access;
            const bool dangerous = (access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                              PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)) != 0;
            const bool read = (access & PROCESS_VM_READ) != 0;
            evidence.source_pid = payload->source_pid;
            evidence.target = cs2_identity_;
            evidence.source = identity_tracker_.observe(payload->source_pid);
            if (dangerous) {
                evidence.anomaly = 0.25f;
                evidence.data_quality = 0.35f;
                evidence.evidence_key = "dangerous_handle";
                evidence.evidence_family = "handle-integrity";
                audit_.write("handle", "CS2 dangerous handle source=" + std::to_string(payload->source_pid));
            } else if (read) {
                evidence.anomaly = 0.08f;
                evidence.data_quality = 0.12f;
                evidence.evidence_key = "read_handle";
                evidence.evidence_family = "handle-observation";
            }
        } else if (type == protocol::EventType::ImageLoaded &&
                   event->pid == cs2_pid_.load(std::memory_order_acquire)) {
            const auto module = module_inventory_.ObserveImageLoad(*event);
            if (module.verdict == modules::Verdict::Suspicious) {
                evidence.anomaly = module.anomaly;
                evidence.data_quality = module.mapped_path.empty() || module.mapped_path_match ? 0.90f : 0.96f;
                evidence.evidence_key = "suspicious_module:" + module.sha256;
                evidence.evidence_family = "module-provenance";
                evidence.target = cs2_identity_;
                const auto sources = graph_.recent_sources(cs2_identity_, graph::EventKind::DangerousHandle, now_ms);
                for (const auto& source : sources) {
                    const auto corr = graph_.correlate(source, cs2_identity_, graph::EventKind::ImageLoaded, now_ms);
                    if (corr.handle_before_module) {
                        evidence.source_pid = source.pid;
                        evidence.source_birth_token = source.birth_token;
                        evidence.source = source;
                        evidence.correlation_edges = corr.supporting_edges;
                        evidence.correlation_id = cs2_identity_.Key() + ":" + module.sha256;
                        evidence.correlation_boost = corr.boost;
                        evidence.anomaly = std::max(evidence.anomaly, 0.98f);
                        evidence.data_quality = std::max(evidence.data_quality, 0.98f);
                        audit_.write("correlation", "same-process-instance handle precedes suspicious module state");
                        break;
                    }
                }
                audit_.write("module", std::string("suspicious module path=") + module.path.string() +
                    " sha256=" + module.sha256 + " publisher=" + module.publisher);
            }
        } else if (type == protocol::EventType::QueueOverflow) {
            evidence.anomaly = 0.0f;
            evidence.data_quality = 0.0f;
            evidence.evidence_key = "queue_overflow_event";
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
        if (aggregate.valid_count >= 20) {
            const auto score = detection::Evaluate(aggregate);
            policy::Evidence evidence{};
            evidence.timestamp_ms = GetTickCount64();
            evidence.anomaly = score.anomaly;
            evidence.data_quality = score.data_quality;
            evidence.event_type = static_cast<std::uint32_t>(protocol::EventType::DriverState);
            evidence.evidence_key = "behavioral_aggregate";
            evidence.evidence_family = "behavioral";
            evidence.target = cs2_identity_;
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
            audit::Record decision_rec{};
            decision_rec.category = "decision";
            decision_rec.message = std::string(DecisionName(result.decision)) +
                " confidence=" + std::to_string(result.confidence) +
                " supporting=" + std::to_string(result.supporting_events) +
                " families=" + std::to_string(result.supporting_families);
            decision_rec.monotonic_ms = GetTickCount64();
            decision_rec.session_id = cs2_identity_.Key();
            decision_rec.target = cs2_identity_;
            audit_.write(decision_rec);
            previous = result.decision;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

} // namespace deac::service
