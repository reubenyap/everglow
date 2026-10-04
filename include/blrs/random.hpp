#pragma once

#include <cstdint>
#include <span>

namespace blrs {

// A failure must throw. Implementations supply independent cryptographic bytes.
class RandomSource {
public:
    virtual ~RandomSource() = default;
    virtual void fill(std::span<std::uint8_t> bytes) = 0;
};

class SystemRandom final : public RandomSource {
public:
    void fill(std::span<std::uint8_t> bytes) override;
};

} // namespace blrs
