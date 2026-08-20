#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>

namespace deac::identity {

struct ProcessIdentity final {
    std::uint64_t pid{};
    std::uint64_t birth_token{}; // QPC-derived stable token for this process instance.
    std::string image_path;

    bool valid() const noexcept { return pid != 0 && birth_token != 0; }
    std::string Key() const;
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
