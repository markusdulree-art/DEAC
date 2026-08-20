#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <cstdint>

namespace deac::updates {

struct Manifest final {
    std::string product;
    std::string version;
    std::string artifact_url;
    std::string artifact_sha256;
    std::string signer_subject;
    std::uint32_t minimum_protocol{};
};

class Manager final {
public:
    Manager(std::string product, std::filesystem::path cache_dir);

    std::optional<Manifest> loadManifest(const std::filesystem::path& manifest_path) const;
    bool verifyArtifactSha256(const std::filesystem::path& artifact, const std::string& expected_hex) const;
    bool verifyAuthenticode(const std::filesystem::path& artifact) const;
    bool accept(const Manifest& manifest) const;

private:
    std::string product_;
    std::filesystem::path cache_dir_;
};

} // namespace deac::updates
