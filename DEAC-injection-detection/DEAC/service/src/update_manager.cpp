#include "update_manager.h"
#include "privacy.h"
#include "deac_protocol.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <windows.h>
#include <wintrust.h>
#include <Softpub.h>
#include <cctype>
#pragma comment(lib, "wintrust.lib")

using json = nlohmann::json;

namespace deac::updates {

Manager::Manager(std::string product, std::filesystem::path cache_dir)
    : product_(std::move(product)), cache_dir_(std::move(cache_dir)) {}

std::optional<Manifest> Manager::loadManifest(const std::filesystem::path& path) const {
    std::ifstream in(path);
    if (!in) return std::nullopt;
    try {
        const auto j = json::parse(in);
        Manifest m{
            j.at("product").get<std::string>(),
            j.at("version").get<std::string>(),
            j.at("artifact_url").get<std::string>(),
            j.at("artifact_sha256").get<std::string>(),
            j.value("signer_subject", ""),
            j.at("minimum_protocol").get<std::uint32_t>()
        };
        return m;
    } catch (...) { return std::nullopt; }
}

bool Manager::verifyArtifactSha256(const std::filesystem::path& artifact, const std::string& expected_hex) const {
    std::ifstream in(artifact, std::ios::binary);
    if (!in) return false;
    std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(in)), {});
    const auto digest = privacy::Sha256(bytes);
    std::string actual = privacy::Hex(digest);
    if (actual.size() != expected_hex.size()) return false;
    for (std::size_t i = 0; i < actual.size(); ++i) {
        if (static_cast<char>(std::tolower(static_cast<unsigned char>(actual[i]))) !=
            static_cast<char>(std::tolower(static_cast<unsigned char>(expected_hex[i])))) return false;
    }
    return true;
}

bool Manager::accept(const Manifest& manifest) const {
    if (manifest.product != product_) return false;
    if (manifest.minimum_protocol > deac::protocol::kProtocolVersion) return false;
    if (manifest.artifact_url.rfind("https://", 0) != 0) return false;
    if (manifest.artifact_sha256.size() != 64) return false;
    for (const char c : manifest.artifact_sha256) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    if (manifest.version.empty()) return false;
    return true;
}

} // namespace deac::updates

bool deac::updates::Manager::verifyAuthenticode(const std::filesystem::path& artifact) const {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = artifact.c_str();
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    const LONG result = WinVerifyTrust(nullptr, &policy, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trust);
    return result == ERROR_SUCCESS;
}
