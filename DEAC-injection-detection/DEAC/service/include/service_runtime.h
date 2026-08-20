#pragma once

#include <atomic>
#include <filesystem>
#include <thread>
#include "audit_log.h"
#include "deac_config.h"
#include "deac_policy.h"
#include "evidence_store.h"
#include "telemetry_engine.h"
#include "module_inventory.h"

namespace deac::service {

class Runtime final {
public:
    Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;
    ~Runtime();

    bool start();
    void stop() noexcept;

private:
    void eventLoop();
    void telemetryLoop();
    void decisionLoop();

    std::atomic_bool stopping_{false};
    std::thread events_;
    std::thread telemetry_;
    std::thread decisions_;
    config::Settings settings_{};
    telemetry::Engine telemetry_engine_;
    policy::Engine policy_engine_;
    evidence::Store evidence_;
    audit::Log audit_;
    modules::Inventory module_inventory_;
    std::atomic<std::uint64_t> cs2_pid_{0};
};

} // namespace deac::service
