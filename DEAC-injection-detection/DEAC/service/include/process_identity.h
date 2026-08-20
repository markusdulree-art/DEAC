#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>

namespace deac::identity {

struct ProcessIdentity final {
    std::uint64_t pid{};
    std::uint64_t birth_token{}; // Windows process-creation FILETIME (100-ns units), unique enough to distinguish PID reuse while retained.
    std::string image_path;

    bool valid() const noexcept { return pid != 0 && birth_token != 0; }
    std::string Key() const;
    bool sameInstance(const ProcessIdentity& other) const noexcept {
        return valid() && other.valid() && pid == other.pid && birth_token == other.birth_token;
    }
};

class Tracker final {
public:
    ProcessIdentity observe(std::uint64_t pid);
    void remove(std::uint64_t pid);
    bool get(std::uint64_t pid, ProcessIdentity& out) const;
    void clear();

private:
    ProcessIdentity query(std::uint64_t pid) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::uint64_t, ProcessIdentity> identities_;
};

} // namespace deac::identity
