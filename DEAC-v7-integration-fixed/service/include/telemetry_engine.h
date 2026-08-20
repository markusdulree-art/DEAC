#pragma once
#include "deac_telemetry.h"
#include <cstddef>

namespace deac::telemetry {
class Engine final {
public:
    void add(const Sample& sample);
    Aggregate aggregate() const;
    std::size_t size() const noexcept;
    void clear();
private:
    static constexpr std::size_t kWindow = 512;
    Sample samples_[kWindow]{};
    std::size_t count_{0};
    std::size_t next_{0};
};
}
