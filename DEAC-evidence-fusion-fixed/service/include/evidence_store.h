#pragma once

#include "deac_policy.h"
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace deac::evidence {

class Store final {
public:
    explicit Store(std::filesystem::path path);

    bool append(const policy::Evidence& evidence);
    std::uint64_t records() const noexcept { return records_; }

private:
    std::filesystem::path path_;
    mutable std::mutex mutex_;
    std::ofstream out_;
    std::uint64_t records_{0};
};

} // namespace deac::evidence
