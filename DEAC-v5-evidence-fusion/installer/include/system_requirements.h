#pragma once
#include <windows.h>

namespace deac::installer {
struct Requirements final {
    bool secure_boot{};
    bool hvci{};
    bool vbs{};
    bool tpm_present{};
    bool meets_policy{};
};
Requirements CheckRequirements();
}
