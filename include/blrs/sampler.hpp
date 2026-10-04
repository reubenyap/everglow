#pragma once

#include "blrs/random.hpp"

#include <array>
#include <cstdint>
#include <gmpxx.h>
#include <span>
#include <stdexcept>

namespace blrs {

class SamplingFailure final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Variable-time reference sampler. With ideal independent input bits, CKS
// sampling and the rational interval coins implement the exact infinite laws.
// Any resource/overflow failure aborts the complete proof attempt. This is not
// a constant-time implementation or a certified bound on finite abort error.
class ExactSampler {
public:
    explicit ExactSampler(RandomSource& source) : source_(source) {}

    // sigma = (31/20) * 2^exponent, with 0 <= exponent <= 30.
    std::int64_t gaussian(unsigned exponent);
    void gaussian(std::span<std::int64_t> output, unsigned exponent);

    // Return the protocol acceptance coin, with z = y + shift. The ordinary
    // probability is min(1, exp((|shift|^2-2<z,shift>)/(2sigma^2))/M).
    bool ordinary_accept(std::span<const std::int64_t> z,
                         std::span<const std::int64_t> shift,
                         unsigned exponent, unsigned rejection_factor);
    // min(1, exp(|shift|^2/(2sigma^2))/(M*cosh(<z,shift>/sigma^2))).
    bool bimodal_accept(std::span<const std::int64_t> z,
                        std::span<const std::int64_t> shift,
                        unsigned exponent, unsigned rejection_factor);

    // Useful independently for testing the exact CKS Bernoulli subroutine.
    bool bernoulli_exp(const mpq_class& nonnegative_exponent);

private:
    bool bit();
    mpz_class uniform_below(const mpz_class& limit);
    bool rational_coin(const mpq_class& probability);
    std::uint64_t uniform_below(std::uint64_t limit);
    bool exp_unit(const mpq_class& exponent);
    std::uint64_t geometric_exp_one();
    bool protocol_coin(const mpq_class& first, const mpq_class& second,
                       unsigned rejection_factor, bool bimodal);

    RandomSource& source_;
    std::array<std::uint8_t, 4096> buffer_{};
    std::size_t next_bit_ = buffer_.size() * 8;
};

} // namespace blrs
