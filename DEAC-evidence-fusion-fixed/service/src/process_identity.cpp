#include "process_identity.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <filesystem>
#include <functional>
#include <sstream>

namespace deac::identity {

std::string ProcessIdentity::Key() const {
    return std::to_string(pid) + ":" + std::to_string(birth_token);
}

ProcessIdentity Tracker::query(std::uint64_t pid) const {
    ProcessIdentity result{};
    result.pid = pid;
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) return {};

    FILETIME create{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) {
        CloseHandle(process);
        return {};
    }

    wchar_t path[32768]{};
    DWORD size = static_cast<DWORD>(std::size(path));
    const bool path_ok = QueryFullProcessImageNameW(process, 0, path, &size) != FALSE;
    CloseHandle(process);

    ULARGE_INTEGER value{};
    value.LowPart = create.dwLowDateTime;
    value.HighPart = create.dwHighDateTime;
    result.birth_token = value.QuadPart;
    if (path_ok && size != 0) {
        std::wstring wide(path, size);
        result.image_path.assign(wide.begin(), wide.end());
    }
#else
    // Portable tests cannot query Windows process state. The test harness uses explicit IDs.
    result.birth_token = pid == 0 ? 0 : pid;
#endif
    return result;
}

ProcessIdentity Tracker::observe(std::uint64_t pid) {
    if (pid == 0) return {};

    const auto queried = query(pid);
    if (!queried.valid()) return {};

    std::scoped_lock lock(mutex_);
    const auto it = identities_.find(pid);
    if (it == identities_.end() || it->second.birth_token != queried.birth_token) {
        identities_[pid] = queried;
    } else if (!queried.image_path.empty() && it->second.image_path.empty()) {
        it->second.image_path = queried.image_path;
    }
    return identities_[pid];
}

void Tracker::remove(std::uint64_t pid) {
    std::scoped_lock lock(mutex_);
    identities_.erase(pid);
}

bool Tracker::get(std::uint64_t pid, ProcessIdentity& out) const {
    std::scoped_lock lock(mutex_);
    const auto it = identities_.find(pid);
    if (it == identities_.end()) return false;
    out = it->second;
    return true;
}

void Tracker::clear() {
    std::scoped_lock lock(mutex_);
    identities_.clear();
}

} // namespace deac::identity
