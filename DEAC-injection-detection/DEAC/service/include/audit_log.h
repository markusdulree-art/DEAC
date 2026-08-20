#pragma once

#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>

namespace deac::audit {

class Log final {
public:
    explicit Log(std::filesystem::path path);
    bool write(std::string_view category, std::string_view message);

private:
    std::filesystem::path path_;
    std::mutex mutex_;
};

} // namespace deac::audit
