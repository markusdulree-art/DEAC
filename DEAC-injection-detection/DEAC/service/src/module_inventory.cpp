#include "module_inventory.h"
#include "privacy.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace deac::modules {
namespace {

std::uint64_t NowMs() {
    return GetTickCount64();
}

bool IsPathUnder(const std::filesystem::path& child, const std::filesystem::path& root) {
    const auto c = child.lexically_normal().wstring();
    auto r = root.lexically_normal().wstring();
    if (r.empty()) return false;
    while (!r.empty() && (r.back() == L'\\' || r.back() == L'/')) r.pop_back();
    if (c.size() < r.size()) return false;
    if (_wcsnicmp(c.c_str(), r.c_str(), r.size()) != 0) return false;
    return c.size() == r.size() || c[r.size()] == L'\\' || c[r.size()] == L'/';
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool ReadFileBounded(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size == 0 || size > 128ull * 1024ull * 1024ull) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    bytes.resize(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<std::size_t>(in.gcount()) == bytes.size();
}

bool VerifySignature(const std::filesystem::path& path, std::string& publisher) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    std::wstring wide = path.wstring();
    file.pcwszFilePath = wide.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    if (status != ERROR_SUCCESS) return false;

    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0, content = 0, format = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wide.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content,
                          &format, &store, &message, nullptr)) {
        return true;
    }

    DWORD signer_size = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size)) {
        std::vector<std::uint8_t> signer(signer_size);
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signer.data(), &signer_size)) {
            auto* info = reinterpret_cast<PCMSG_SIGNER_INFO>(signer.data());
            CERT_INFO cert_info{};
            cert_info.Issuer = info->Issuer;
            cert_info.SerialNumber = info->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, encoding, 0, CERT_FIND_SUBJECT_CERT, &cert_info, nullptr);
            if (cert) {
                char name[512]{};
                if (CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                       nullptr, name, sizeof(name)) > 1) {
                    publisher = name;
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return true;
}

std::string ClassifyPublisher(const std::string& publisher) {
    return Lower(publisher);
}

} // namespace

const char* ToString(Provenance value) noexcept {
    switch (value) {
        case Provenance::WindowsSystem: return "windows-system";
        case Provenance::ValveSigned: return "valve-signed";
        case Provenance::SteamSigned: return "steam-signed";
        case Provenance::MicrosoftSigned: return "microsoft-signed";
        case Provenance::TrustedThirdPartySigned: return "trusted-third-party-signed";
        case Provenance::GameRootUnsigned: return "game-root-unsigned";
        case Provenance::ExternalUnsigned: return "external-unsigned";
        case Provenance::Missing: return "missing";
        default: return "unknown";
    }
}

const char* ToString(Verdict value) noexcept {
    switch (value) {
        case Verdict::Trusted: return "trusted";
        case Verdict::Observe: return "observe";
        case Verdict::Suspicious: return "suspicious";
        default: return "observe";
    }
}

std::filesystem::path Inventory::Normalize(const std::filesystem::path& path) {
    std::error_code ec;
    auto absolute = std::filesystem::absolute(path, ec);
    if (ec) absolute = path;
    auto canonical = std::filesystem::weakly_canonical(absolute, ec);
    return ec ? absolute.lexically_normal() : canonical;
}

bool Inventory::AttachToProcess(std::uint64_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!process) return false;
    wchar_t buffer[32768]{};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    const bool ok = QueryFullProcessImageNameW(process, 0, buffer, &size) != FALSE;
    CloseHandle(process);
    if (!ok || size == 0) return false;

    const auto image = Normalize(std::filesystem::path(buffer));
    std::lock_guard lock(mutex_);
    game_root_ = image.parent_path();
    wchar_t system_dir[MAX_PATH]{};
    const UINT len = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (len != 0 && len < MAX_PATH) windows_root_ = Normalize(std::filesystem::path(system_dir));
    return true;
}

bool Inventory::IsTrustedRoot(const std::filesystem::path& path) const {
    return IsPathUnder(path, windows_root_) || IsPathUnder(path, game_root_);
}

ModuleAssessment Inventory::Assess(std::uint64_t pid, const std::filesystem::path& raw_path,
                                   std::uintptr_t base, std::uint32_t image_size) {
    ModuleAssessment result{};
    result.pid = pid;
    result.base = base;
    result.image_size = image_size;
    result.path = Normalize(raw_path);
    result.first_seen_ms = result.last_seen_ms = NowMs();

    std::vector<std::uint8_t> contents;
    if (!ReadFileBounded(result.path, contents)) {
        result.provenance = Provenance::Missing;
        result.verdict = Verdict::Suspicious;
        result.anomaly = 0.90f;
        return result;
    }

    try {
        result.sha256 = privacy::Hex(privacy::Sha256(contents));
    } catch (...) {
        result.verdict = Verdict::Observe;
        result.anomaly = 0.25f;
    }

    std::string publisher;
    const bool signed_valid = VerifySignature(result.path, publisher);
    result.publisher = publisher;
    const auto publisher_lower = ClassifyPublisher(publisher);

    if (IsPathUnder(result.path, windows_root_)) {
        result.provenance = signed_valid ? Provenance::MicrosoftSigned : Provenance::WindowsSystem;
        result.verdict = Verdict::Trusted;
        result.anomaly = signed_valid ? 0.0f : 0.05f;
    } else if (signed_valid && publisher_lower.find("valve") != std::string::npos) {
        result.provenance = Provenance::ValveSigned;
        result.verdict = Verdict::Trusted;
        result.anomaly = 0.0f;
    } else if (signed_valid && publisher_lower.find("steam") != std::string::npos) {
        result.provenance = Provenance::SteamSigned;
        result.verdict = Verdict::Trusted;
        result.anomaly = 0.0f;
    } else if (signed_valid && publisher_lower.find("microsoft") != std::string::npos) {
        result.provenance = Provenance::MicrosoftSigned;
        result.verdict = Verdict::Trusted;
        result.anomaly = 0.0f;
    } else if (signed_valid) {
        // Signed third-party modules are not automatically malicious. Keep them observable.
        result.provenance = Provenance::TrustedThirdPartySigned;
        result.verdict = Verdict::Observe;
        result.anomaly = IsTrustedRoot(result.path) ? 0.05f : 0.20f;
    } else if (IsPathUnder(result.path, game_root_)) {
        // Steam/Valve content is normally established in the initial inventory. An unsigned
        // module already present at service startup is therefore treated as baseline content,
        // while a new unsigned hash appearing later is materially more suspicious.
        result.provenance = Provenance::GameRootUnsigned;
        const bool known_baseline = baseline_hashes_.find(result.sha256) != baseline_hashes_.end();
        result.verdict = known_baseline ? Verdict::Observe : Verdict::Suspicious;
        result.anomaly = known_baseline ? 0.05f : 0.82f;
    } else {
        result.provenance = Provenance::ExternalUnsigned;
        result.verdict = Verdict::Suspicious;
        result.anomaly = 0.95f;
    }
    return result;
}

std::vector<ModuleAssessment> Inventory::Refresh(std::uint64_t pid) {
    if (!AttachToProcess(pid)) return {};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                                static_cast<DWORD>(pid));
    if (snapshot == INVALID_HANDLE_VALUE) return {};

    std::vector<ModuleAssessment> current;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            auto assessment = Assess(pid, entry.szExePath,
                                     reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
                                     entry.modBaseSize);
            current.push_back(assessment);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::lock_guard lock(mutex_);
    if (!baseline_established_) {
        for (const auto& item : current) {
            if (!item.sha256.empty() && IsPathUnder(item.path, game_root_)) {
                baseline_hashes_.insert(item.sha256);
            }
        }
        baseline_established_ = true;
    }

    // Re-assess game-root unsigned modules now that the baseline exists.
    for (auto& item : current) {
        if (item.provenance == Provenance::GameRootUnsigned &&
            baseline_hashes_.find(item.sha256) != baseline_hashes_.end()) {
            item.verdict = Verdict::Observe;
            item.anomaly = 0.05f;
        }
    }

    std::unordered_map<std::string, ModuleAssessment> next;
    next.reserve(current.size());
    for (auto& item : current) {
        const auto key_w = item.path.wstring();
        const std::string key(key_w.begin(), key_w.end());
        auto existing = modules_.find(key);
        if (existing != modules_.end()) item.first_seen_ms = existing->second.first_seen_ms;
        next[key] = item;
    }
    modules_.swap(next);
    return current;
}

ModuleAssessment Inventory::ObserveImageLoad(const protocol::Event& event) {
    ModuleAssessment assessment{};
    if (event.payload_size < sizeof(protocol::ImagePayload)) return assessment;
    const auto* payload = reinterpret_cast<const protocol::ImagePayload*>(event.payload);
    const std::size_t count = std::min<std::size_t>(std::size(payload->image_name),
                                                    payload->image_name[0] ? std::size(payload->image_name) : 0);
    std::wstring path(payload->image_name, payload->image_name + count);
    if (const auto nul = path.find(L'\0'); nul != std::wstring::npos) path.resize(nul);
    assessment = Assess(event.pid, path,
                        static_cast<std::uintptr_t>(payload->image_base), payload->image_size);

    std::lock_guard lock(mutex_);
    const auto key_w = assessment.path.wstring();
    const std::string key(key_w.begin(), key_w.end());
    auto existing = modules_.find(key);
    if (existing != modules_.end()) assessment.first_seen_ms = existing->second.first_seen_ms;
    assessment.last_seen_ms = NowMs();
    modules_[key] = assessment;
    return assessment;
}

std::vector<MemoryAssessment> Inventory::ScanExecutablePrivateRegions(std::uint64_t pid) const {
    std::vector<MemoryAssessment> findings;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                 static_cast<DWORD>(pid));
    if (!process) return findings;

    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto address = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);

    while (address < maximum) {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T queried = VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (queried != sizeof(mbi) || mbi.RegionSize == 0) break;

        const auto protection = mbi.Protect & 0xFFu;
        const bool executable = protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
        const bool writable = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
                              protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
        const bool private_region = mbi.Type == MEM_PRIVATE;

        if (mbi.State == MEM_COMMIT && executable && private_region) {
            MemoryAssessment finding{};
            finding.pid = pid;
            finding.base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            finding.region_size = mbi.RegionSize;
            finding.protection = protection;
            finding.type = mbi.Type;
            finding.executable = executable;
            finding.writable = writable;
            finding.private_region = private_region;

            // A PE header in a private executable allocation is a useful manual-map signal.
            // We only read 0x1000 bytes from the region and never treat the contents as trusted.
            std::array<std::uint8_t, 0x1000> header{};
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(process, mbi.BaseAddress, header.data(), header.size(), &bytes_read) && bytes_read >= 0x40) {
                if (header[0] == 'M' && header[1] == 'Z') {
                    const std::uint32_t pe_offset =
                        static_cast<std::uint32_t>(header[0x3C]) |
                        (static_cast<std::uint32_t>(header[0x3D]) << 8) |
                        (static_cast<std::uint32_t>(header[0x3E]) << 16) |
                        (static_cast<std::uint32_t>(header[0x3F]) << 24);
                    if (pe_offset + 4 <= bytes_read &&
                        header[pe_offset] == 'P' && header[pe_offset + 1] == 'E' &&
                        header[pe_offset + 2] == 0 && header[pe_offset + 3] == 0) {
                        finding.pe_header = true;
                    }
                }
            }

            if (finding.pe_header && finding.writable) {
                finding.anomaly = 0.99f;
                finding.reason = "private executable+writable PE region";
            } else if (finding.pe_header) {
                finding.anomaly = 0.94f;
                finding.reason = "private executable PE region";
            } else if (finding.writable) {
                finding.anomaly = 0.55f;
                finding.reason = "private executable+writable region";
            } else {
                finding.anomaly = 0.25f;
                finding.reason = "private executable region";
            }
            findings.push_back(finding);
        }

        const auto next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= address) break;
        address = next;
    }

    CloseHandle(process);
    return findings;
}

InventorySummary Inventory::Summary() const {
    std::lock_guard lock(mutex_);
    InventorySummary s{};
    s.total = static_cast<std::uint32_t>(modules_.size());
    for (const auto& [_, module] : modules_) {
        switch (module.verdict) {
            case Verdict::Trusted: ++s.trusted; break;
            case Verdict::Observe: ++s.observed; break;
            case Verdict::Suspicious: ++s.suspicious; break;
        }
    }
    return s;
}

std::vector<ModuleAssessment> Inventory::Snapshot() const {
    std::lock_guard lock(mutex_);
    std::vector<ModuleAssessment> result;
    result.reserve(modules_.size());
    for (const auto& [_, module] : modules_) result.push_back(module);
    return result;
}

} // namespace deac::modules
