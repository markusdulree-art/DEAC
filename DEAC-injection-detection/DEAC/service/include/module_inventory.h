#pragma once

#include "deac_protocol.h"
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace deac::modules {

enum class Provenance : std::uint32_t {
    Unknown = 0,
    WindowsSystem = 1,
    ValveSigned = 2,
    SteamSigned = 3,
    MicrosoftSigned = 4,
    TrustedThirdPartySigned = 5,
    GameRootUnsigned = 6,
    ExternalUnsigned = 7,
    Missing = 8,
};

enum class Verdict : std::uint32_t {
    Trusted = 0,
    Observe = 1,
    Suspicious = 2,
};

struct ModuleAssessment final {
    std::uint64_t pid{};
    std::uintptr_t base{};
    std::uint32_t image_size{};
    std::filesystem::path path;
    std::string sha256;
    std::string publisher;
    Provenance provenance{Provenance::Unknown};
    Verdict verdict{Verdict::Observe};
    float anomaly{};
    std::uint64_t first_seen_ms{};
    std::uint64_t last_seen_ms{};
};

struct MemoryAssessment final {
    std::uint64_t pid{};
    std::uintptr_t base{};
    std::size_t region_size{};
    std::uint32_t protection{};
    std::uint32_t type{};
    bool executable{};
    bool writable{};
    bool private_region{};
    bool pe_header{};
    float anomaly{};
    const char* reason{};
};

struct InventorySummary final {
    std::uint32_t total{};
    std::uint32_t trusted{};
    std::uint32_t observed{};
    std::uint32_t suspicious{};
};

class Inventory final {
public:
    Inventory() = default;

    // Establishes the CS2 executable root and performs an initial module snapshot.
    bool AttachToProcess(std::uint64_t pid);

    // Reconciles the current module set. Safe to call periodically.
    std::vector<ModuleAssessment> Refresh(std::uint64_t pid);

    // Inspects executable private-memory regions without reading arbitrary game memory.
    // Only region metadata and the first PE headers are sampled.
    std::vector<MemoryAssessment> ScanExecutablePrivateRegions(std::uint64_t pid) const;

    // Correlates a kernel image-load event with the current inventory.
    ModuleAssessment ObserveImageLoad(const protocol::Event& event);

    InventorySummary Summary() const;
    std::vector<ModuleAssessment> Snapshot() const;

private:
    ModuleAssessment Assess(std::uint64_t pid, const std::filesystem::path& path,
                            std::uintptr_t base, std::uint32_t image_size);
    bool IsTrustedRoot(const std::filesystem::path& path) const;
    static std::filesystem::path Normalize(const std::filesystem::path& path);

    mutable std::mutex mutex_;
    std::filesystem::path game_root_;
    std::filesystem::path windows_root_;
    std::unordered_map<std::string, ModuleAssessment> modules_;
    std::unordered_set<std::string> baseline_hashes_;
    bool baseline_established_{false};
};

const char* ToString(Provenance value) noexcept;
const char* ToString(Verdict value) noexcept;

} // namespace deac::modules
