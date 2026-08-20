#pragma once
#include <filesystem>
#include <string>

namespace deac::installer {
class ServiceInstaller final {
public:
    bool installDriver(const std::filesystem::path& sysPath) const;
    bool removeDriver() const;
    bool installService(const std::filesystem::path& exePath) const;
    bool removeService() const;
};
}
