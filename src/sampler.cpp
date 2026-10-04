#include "blrs/sampler.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <utility>
#include <vector>

namespace blrs {
namespace {

// Resource exhaustion has an explicit failure result, never a substituted
// sample. The caller must abandon every commitment in the current attempt.
constexpr std::size_t work_limit = 4096;
constexpr std::size_t proposal_limit = 1U << 20;

mpz_class integer(std::uint64_t value) {
    mpz_class result;
    mpz_import(result.get_mpz_t(), 1, 1, sizeof(value), 0, 0, &value);
    return result;
}

mpz_class integer(std::int64_t value) {
    const auto magnitude = value < 0
        ? static_cast<std::uint64_t>(-(value + 1)) + 1
        : static_cast<std::uint64_t>(value);
    auto result = integer(magnitude);
    if (value < 0) result = -result;
    return result;
}

mpq_class variance(unsigned exponent) {
    if (exponent > 30) throw std::invalid_argument("unsupported Gaussian exponent");
    mpz_class numerator = 961;
    numerator <<= 2 * exponent;
    mpq_class result(numerator, 400);
    result.canonicalize();
    return result;
}

std::pair<mpz_class, mpz_class> moments(std::span<const std::int64_t> z,
                                      std::span<const std::int64_t> shift) {
    if (z.size() != shift.size()) throw std::invalid_argument("sampler vector lengths differ");
    mpz_class norm = 0, dot = 0;
    for (std::size_t i = 0; i < z.size(); ++i) {
        const auto v = integer(shift[i]);
        norm += v * v;
        dot += integer(z[i]) * v;
    }
    return {norm, dot};
}

// Positive Taylor series with a geometric upper bound on the remaining tail.
// For n+2 > x, successive tail terms have ratio <= x/(n+2).
struct ExponentialInterval {
    explicit ExponentialInterval(mpq_class value) : x(std::move(value)) {}

    bool refine() {
        ++n;
        term *= x;
        term /= n;
        lower += term;
        const mpq_class ratio = x / (n + 2);
        if (ratio >= 1) return false;
        const mpq_class next = term * x / (n + 1);
        upper = lower + next / (1 - ratio);
        return true;
    }

    mpq_class x, term = 1, lower = 1, upper = 1;
    unsigned long n = 0;
};

mpq_class capped(const mpq_class& value) {
    return value >= 1 ? mpq_class(1) : value;
}

} // namespace

bool ExactSampler::bit() {
    if (next_bit_ == buffer_.size() * 8) {
        source_.fill(buffer_);
        next_bit_ = 0;
    }
    const bool result = ((buffer_[next_bit_ / 8] >> (next_bit_ % 8)) & 1U) != 0;
    ++next_bit_;
    return result;
}

mpz_class ExactSampler::uniform_below(const mpz_class& limit) {
    if (limit <= 0) throw std::invalid_argument("uniform limit must be positive");
    if (limit == 1) return 0;
    const mpz_class maximum = limit - 1;
    const std::size_t width = mpz_sizeinbase(maximum.get_mpz_t(), 2);
    if (width > work_limit) throw SamplingFailure("uniform precision limit reached");
    for (std::size_t attempt = 0; attempt < proposal_limit; ++attempt) {
        mpz_class value = 0;
        for (std::size_t i = 0; i < width; ++i) if (bit()) mpz_setbit(value.get_mpz_t(), i);
        if (value < limit) return value;
    }
    throw SamplingFailure("uniform proposal limit reached");
}

std::uint64_t ExactSampler::uniform_below(std::uint64_t limit) {
    if (limit == 0) throw std::invalid_argument("uniform limit must be positive");
    if (limit == 1) return 0;
    const unsigned width = static_cast<unsigned>(std::bit_width(limit - 1));
    for (std::size_t attempt = 0; attempt < proposal_limit; ++attempt) {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i) if (bit()) value |= std::uint64_t{1} << i;
        if (value < limit) return value;
    }
    throw SamplingFailure("uniform proposal limit reached");
}

bool ExactSampler::rational_coin(const mpq_class& probability) {
    if (probability < 0 || probability > 1) throw std::invalid_argument("invalid rational probability");
    if (probability == 0) return false;
    if (probability == 1) return true;
    mpq_class reduced = probability;
    reduced.canonicalize();
    return uniform_below(reduced.get_den()) < reduced.get_num();
}

bool ExactSampler::exp_unit(const mpq_class& exponent) {
    for (unsigned long k = 1; k <= work_limit; ++k) {
        if (!rational_coin(exponent / k)) return (k % 2) != 0;
    }
    throw SamplingFailure("exponential coin work limit reached");
}

bool ExactSampler::bernoulli_exp(const mpq_class& nonnegative_exponent) {
    if (nonnegative_exponent < 0) throw std::invalid_argument("negative exponential coin exponent");
    mpq_class remaining = nonnegative_exponent;
    remaining.canonicalize();
    for (std::size_t i = 0; i < proposal_limit; ++i) {
        if (remaining <= 1) return exp_unit(remaining);
        if (!exp_unit(mpq_class(1))) return false;
        remaining -= 1;
    }
    throw SamplingFailure("exponential coin integer part limit reached");
}

std::uint64_t ExactSampler::geometric_exp_one() {
    for (std::uint64_t value = 0; value < proposal_limit; ++value) {
        if (!exp_unit(mpq_class(1))) return value;
    }
    throw SamplingFailure("geometric proposal limit reached");
}

std::int64_t ExactSampler::gaussian(unsigned exponent) {
    const mpq_class sigma_squared = variance(exponent);
    const std::uint64_t t = (std::uint64_t{31} << exponent) / 20 + 1;
    for (std::size_t proposal = 0; proposal < proposal_limit; ++proposal) {
        // CKS Algorithms 2 and 3, independently implemented from the paper:
        // https://arxiv.org/abs/2004.00010 . Exact discrete Laplace proposal.
        const bool negative = bit();
        std::uint64_t u = 0;
        bool found = false;
        for (std::size_t attempt = 0; attempt < proposal_limit; ++attempt) {
            u = uniform_below(t);
            if (bernoulli_exp(mpq_class(integer(u), integer(t)))) {
                found = true;
                break;
            }
        }
        if (!found) throw SamplingFailure("Laplace proposal limit reached");
        const std::uint64_t v = geometric_exp_one();
        if (v > (std::numeric_limits<std::uint64_t>::max() - u) / t)
            throw SamplingFailure("Laplace magnitude overflow");
        const std::uint64_t magnitude = v * t + u;
        if (negative && magnitude == 0) continue;
        if (magnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            throw SamplingFailure("Gaussian signed output overflow");
        const mpq_class distance = mpq_class(integer(magnitude)) - sigma_squared / integer(t);
        if (bernoulli_exp(distance * distance / (2 * sigma_squared))) {
            const auto result = static_cast<std::int64_t>(magnitude);
            return negative ? -result : result;
        }
    }
    throw SamplingFailure("Gaussian proposal limit reached");
}

void ExactSampler::gaussian(std::span<std::int64_t> output, unsigned exponent) {
    for (auto& value : output) value = gaussian(exponent);
}

bool ExactSampler::protocol_coin(const mpq_class& first, const mpq_class& second,
                                unsigned rejection_factor, bool bimodal) {
    if (rejection_factor == 0) throw std::invalid_argument("zero rejection factor");
    if (first == 0 && (!bimodal || second == 0))
        return rational_coin(mpq_class(1, rejection_factor));
    if (!bimodal && first >= mpq_class(rejection_factor - 1)) return true;
    const bool reciprocal = first < 0;
    ExponentialInterval a(reciprocal ? -first : first);
    ExponentialInterval b(second < 0 ? -second : second);
    mpz_class uniform_prefix = 0, denominator = 1;
    for (std::size_t iteration = 0; iteration < work_limit; ++iteration) {
        const bool a_ready = a.refine();
        const bool b_ready = !bimodal || b.refine();
        uniform_prefix <<= 1;
        if (bit()) ++uniform_prefix;
        denominator <<= 1;
        if (!a_ready || !b_ready) continue;
        mpq_class lower, upper;
        if (bimodal) {
            // E >= 1 and (E+1/E)/2 increases on [1,infinity).
            const mpq_class cosh_lower = (b.lower + 1 / b.lower) / 2;
            const mpq_class cosh_upper = (b.upper + 1 / b.upper) / 2;
            lower = a.lower / (rejection_factor * cosh_upper);
            upper = a.upper / (rejection_factor * cosh_lower);
        } else if (reciprocal) {
            lower = 1 / (rejection_factor * a.upper);
            upper = 1 / (rejection_factor * a.lower);
        } else {
            lower = a.lower / rejection_factor;
            upper = a.upper / rejection_factor;
        }
        lower = capped(lower);
        upper = capped(upper);
        if (mpq_class(uniform_prefix + 1, denominator) <= lower) return true;
        if (mpq_class(uniform_prefix, denominator) >= upper) return false;
    }
    throw SamplingFailure("protocol coin precision limit reached");
}

bool ExactSampler::ordinary_accept(std::span<const std::int64_t> z,
                                  std::span<const std::int64_t> shift,
                                  unsigned exponent, unsigned rejection_factor) {
    const auto [norm, dot] = moments(z, shift);
    return protocol_coin(mpq_class(norm - 2 * dot) / (2 * variance(exponent)),
                         mpq_class(0), rejection_factor, false);
}

bool ExactSampler::bimodal_accept(std::span<const std::int64_t> z,
                                 std::span<const std::int64_t> shift,
                                 unsigned exponent, unsigned rejection_factor) {
    const auto [norm, dot] = moments(z, shift);
    const auto sigma_squared = variance(exponent);
    return protocol_coin(mpq_class(norm) / (2 * sigma_squared),
                         mpq_class(dot) / sigma_squared, rejection_factor, true);
}

} // namespace blrs
