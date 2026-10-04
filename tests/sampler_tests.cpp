#include "blrs/sampler.hpp"

#include <array>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Labelled sampler-tests-v1 source. Never used for benchmark cryptographic
// randomness. Little-endian SplitMix64 fixes a cross-language test bitstream.
class TestRandom final : public blrs::RandomSource {
public:
    void fill(std::span<std::uint8_t> output) override {
        for (auto& byte : output) {
            if (remaining_ == 0) {
                state_ += 0x9e3779b97f4a7c15ULL;
                word_ = state_;
                word_ = (word_ ^ (word_ >> 30)) * 0xbf58476d1ce4e5b9ULL;
                word_ = (word_ ^ (word_ >> 27)) * 0x94d049bb133111ebULL;
                word_ ^= word_ >> 31;
                remaining_ = 8;
            }
            byte = static_cast<std::uint8_t>(word_);
            word_ >>= 8;
            --remaining_;
        }
    }
private:
    std::uint64_t state_ = 0x35eb12347c91a208ULL, word_ = 0;
    unsigned remaining_ = 0;
};

class FailingRandom final : public blrs::RandomSource {
public:
    void fill(std::span<std::uint8_t>) override { throw std::runtime_error("entropy failure"); }
};

void check_vectors() {
    TestRandom random;
    blrs::ExactSampler sampler(random);
    // Calculated independently with Fraction-based CKS Algorithms 1-3 and the
    // same bitstream, not generated from this C++ implementation.
    constexpr std::array<std::int64_t, 16> small{1,-1,1,2,-1,0,-1,-2,-1,-2,-2,0,-2,-1,-1,0};
    constexpr std::array<std::int64_t, 8> rho{13187,45752,4316,49260,-36227,-1078,3795,-48907};
    constexpr std::array<std::int64_t, 8> core{593073,-245218,241490,-238416,-167007,423606,44581,244279};
    for (auto expected : small) require(sampler.gaussian(0) == expected, "small Gaussian vector mismatch");
    for (auto expected : rho) require(sampler.gaussian(15) == expected, "rho Gaussian vector mismatch");
    for (auto expected : core) require(sampler.gaussian(18) == expected, "core Gaussian vector mismatch");
}

void check_distributions() {
    TestRandom random;
    blrs::ExactSampler sampler(random);
    constexpr unsigned count = 20000;
    double sum = 0, squares = 0;
    for (unsigned i = 0; i < count; ++i) {
        const auto value = sampler.gaussian(0);
        sum += static_cast<double>(value);
        squares += static_cast<double>(value) * static_cast<double>(value);
    }
    require(std::abs(sum / count) < 0.08, "Gaussian mean sanity check failed");
    require(std::abs(squares / count - 2.4025) < 0.15, "Gaussian scale sanity check failed");

    constexpr unsigned coin_count = 6000;
    unsigned exp_count = 0, ordinary_count = 0, bimodal_count = 0;
    const std::array<std::int64_t, 1> z{1}, shift{1};
    for (unsigned i = 0; i < coin_count; ++i) {
        exp_count += sampler.bernoulli_exp(mpq_class(1, 2));
        ordinary_count += sampler.ordinary_accept(z, shift, 0, 4);
        bimodal_count += sampler.bimodal_accept(z, shift, 0, 2);
    }
    const double sigma_squared = 2.4025;
    require(std::abs(static_cast<double>(exp_count) / coin_count - std::exp(-0.5)) < 0.04,
            "exact exponential coin sanity check failed");
    require(std::abs(static_cast<double>(ordinary_count) / coin_count - std::exp(-1/(2*sigma_squared))/4) < 0.04,
            "ordinary acceptance coin sanity check failed");
    require(std::abs(static_cast<double>(bimodal_count) / coin_count - std::exp(1/(2*sigma_squared))/(2*std::cosh(1/sigma_squared))) < 0.04,
            "bimodal acceptance coin sanity check failed");
}

void check_failures() {
    TestRandom random;
    blrs::ExactSampler sampler(random);
    require(sampler.bernoulli_exp(mpq_class(0)), "zero exponent must accept");
    const std::array<std::int64_t, 1> z{-100}, shift{100};
    require(sampler.ordinary_accept(z, shift, 0, 4), "clipped ordinary acceptance must be one");
    bool failed = false;
    try { (void)sampler.gaussian(31); } catch (const std::invalid_argument&) { failed = true; }
    require(failed, "unsupported Gaussian scale accepted");
    failed = false;
    try { (void)sampler.ordinary_accept(z, shift, 0, 0); } catch (const std::invalid_argument&) { failed = true; }
    require(failed, "zero rejection factor accepted");
    failed = false;
    try { (void)sampler.bimodal_accept(z, {}, 0, 2); } catch (const std::invalid_argument&) { failed = true; }
    require(failed, "mismatched rejection vectors accepted");
    FailingRandom failing;
    blrs::ExactSampler failing_sampler(failing);
    failed = false;
    try { (void)failing_sampler.gaussian(18); } catch (const std::runtime_error&) { failed = true; }
    require(failed, "entropy failure did not propagate");
}

void check_optimized_core() {
    TestRandom positive_random, negative_random;
    blrs::ExactSampler positive(positive_random), negative(negative_random);
    const std::array<std::int64_t, 3> z{30000, 40000, -20000};
    const std::array<std::int64_t, 3> shift{10000, -8000, 6000};
    const std::array<std::int64_t, 3> negated_shift{-10000, 8000, -6000};
    unsigned accepted = 0;
    for (unsigned i = 0; i < 256; ++i) {
        const auto decision = positive.bimodal_accept(z, shift, 14, 2);
        require(decision == negative.bimodal_accept(z, negated_shift, 14, 2),
                "optimized bimodal coin changed under the global sign");
        accepted += decision;
    }
    require(accepted > 0 && accepted < 256, "optimized coin did not exercise both decisions");

    TestRandom gaussian_random;
    blrs::ExactSampler gaussian(gaussian_random);
    constexpr unsigned count = 4096;
    constexpr double sigma = 25395.2;
    double sum = 0, squares = 0;
    for (unsigned i = 0; i < count; ++i) {
        const auto value = static_cast<double>(gaussian.gaussian(14));
        sum += value;
        squares += value*value;
    }
    require(std::abs(sum/count) < 0.09*sigma, "optimized Gaussian mean sanity check failed");
    require(std::abs(squares/count/(sigma*sigma)-1) < 0.12,
            "optimized Gaussian scale sanity check failed");
}

} // namespace

int main() {
    try {
        check_vectors();
        check_distributions();
        check_failures();
        check_optimized_core();
        std::cout << "sampler tests passed (vectors, distribution sanity, optimized sign symmetry, failure contracts)\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
