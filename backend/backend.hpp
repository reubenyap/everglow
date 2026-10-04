#pragma once
#include "blrs/relation.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace blrs {
class ExactSampler;
enum class CoreProfile : std::uint8_t { Ordinary, Bimodal };
constexpr std::int64_t z1_coefficient_bound(CoreProfile profile) {
    return profile == CoreProfile::Bimodal ? 1377909 : 22046544;
}
using SignedPoly = std::array<std::int64_t, 64>;
using Seed = std::array<std::uint8_t, 32>;
struct ProofCrs {
    std::vector<QPoly> A1;       // 20 x 23, row major
    std::vector<QPoly> A2prime;  // 20 x 75, row major
    std::vector<QPoly> Bprime;   // 23 x 75, row major
};
struct Opening {
    std::array<QPoly, 23> small{};
    std::array<QPoly, 23> message{};
    std::array<SignedPoly, 95> rho{};
    std::array<QPoly, 20> tA1{}, tA2{};
    std::array<QPoly, 23> tB{};
};
struct BaseProof {
    std::array<QPoly, 23> tB{};
    std::array<QPoly, 5> base_h{};
    std::array<QPoly, 20> tA1{};
    SignedPoly c{};
    std::array<SignedPoly, 20> hint{};
    std::array<SignedPoly, 23> z1{};
    std::array<SignedPoly, 75> z21{};
};
class Backend {
public:
    explicit Backend(const ProofCrs&, CoreProfile profile = CoreProfile::Ordinary);
    ~Backend();
    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    void commit(Opening&) const;
    std::optional<BaseProof> prove_one_attempt(Opening&,
        std::span<const SparseEvaluation>, Seed base_hash, const Seed& mask_seed,
        ExactSampler&) const;
    bool verify(const BaseProof&, std::span<const SparseEvaluation>, Seed base_hash) const;
    CoreProfile profile() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
