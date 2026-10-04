#pragma once

#include "blrs/random.hpp"
#include "blrs/transcript.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace blrs {

inline constexpr std::uint16_t field_prime = 65437;
inline constexpr std::size_t degree = 64;
inline constexpr std::size_t secret_width = 18;
inline constexpr std::size_t ring_size = 65536;
inline constexpr std::size_t projection_rows = 18;
inline constexpr std::uint64_t proof_modulus = 1151179879138398721ULL;
inline constexpr std::uint64_t field_lift = 17592186058933ULL;
inline constexpr std::array<std::size_t, 5> radices{8, 8, 8, 8, 16};
inline constexpr std::size_t small_polynomials = 23;
inline constexpr std::size_t message_polynomials = 17;
inline constexpr std::size_t evaluation_variables = 80;
inline constexpr std::size_t scalar_evaluations = 1133;
inline constexpr std::int64_t range_response_cap = 9751757;

using FieldPoly = std::array<std::uint16_t, degree>;
using Secret = std::array<FieldPoly, secret_width>;
using Key = std::array<FieldPoly, 2>;
using StatementMatrix = std::array<std::array<FieldPoly, secret_width>, 2>;
using SignedPoly = std::array<std::int64_t, degree>;
using QPoly = std::array<std::uint64_t, degree>;
using SmallWitness = std::array<SignedPoly, small_polynomials>;
using MessageWitness = std::array<SignedPoly, message_polynomials>;
using BinaryWitness = std::array<SignedPoly, 24>;

struct StatementSetup {
    StatementMatrix key_matrix{};
    StatementMatrix link_matrix{};
};

StatementSetup setup(RandomSource& random);
Secret generate_secret(RandomSource& random);
Key apply_matrix(const StatementMatrix& matrix, const Secret& secret);
Key public_key(const StatementSetup& parameters, const Secret& secret);
Key link_tag(const StatementSetup& parameters, const Secret& secret);
bool canonical_key(const Key& key);
std::array<std::size_t, 5> index_digits(std::size_t index);

// Projected tables are column-major; each column has 144 field coefficients.
struct CoefficientMatrix {
    std::size_t rows = 0;
    std::size_t columns = 0;
    std::vector<std::uint16_t> coefficients;
    std::span<const std::uint16_t> column(std::size_t index) const;
};

struct Projection {
    std::size_t columns = 0;
    std::vector<std::uint16_t> coefficients; // 18 row-major rows
};

Projection derive_projection(std::span<const std::uint8_t> prefix, unsigned stage);
CoefficientMatrix fold_ring(std::span<const Key> ring, const Projection& projection);
CoefficientMatrix fold_matrix(const CoefficientMatrix& table, const Projection& projection);
std::array<std::uint16_t, 144> witness_column(const CoefficientMatrix& table,
                                             std::size_t original_index,
                                             unsigned completed_folds);

struct SignedWitness {
    SmallWitness small{};
    MessageWitness message{}; // core b,h_1,...,h_4 followed by four y3 polynomials
};

SignedWitness make_witness(const Secret& secret, std::size_t index, int sign,
                          const std::array<std::array<std::uint16_t, 144>, 4>& blocks);
BinaryWitness binary_map(const SignedWitness& witness);
bool check_semantic_relation(const StatementSetup& parameters, const Key& tag,
                             const std::array<Projection, 4>& projections,
                             const CoefficientMatrix& terminal, const SignedWitness& witness);

Bytes encode_key(const Key& key);
Bytes encode_keys(std::span<const Key> keys);
Bytes encode_q_polynomials(std::span<const QPoly> polynomials);
Bytes encode_signed_coefficients(std::span<const std::int64_t> coefficients);
Identifier statement_identifier(const StatementSetup& parameters,
                                std::span<const std::uint8_t> context);
Identifier ring_identifier(const Identifier& statement_id, std::span<const Key> ring);

using RangeMatrix = std::vector<std::int8_t>; // 256 x 1536, row-major
RangeMatrix derive_range_matrix(std::span<const std::uint8_t> prefix);
std::array<std::int64_t, 256> project_binary(const RangeMatrix& projection,
                                           const BinaryWitness& binary);

struct LinearTerm {
    std::size_t index;
    QPoly coefficient;
};
struct QuadraticTerm {
    std::size_t left;
    std::size_t right;
    QPoly coefficient;
};
struct SparseEvaluation {
    std::vector<LinearTerm> linear;
    std::vector<QuadraticTerm> quadratic;
    QPoly constant{};
};

// Variables are P0,sigma(P0),...,P22,sigma(P22),M0,sigma(M0),...,M16,sigma(M16).
std::vector<SparseEvaluation> compile_evaluations(const StatementSetup& parameters,
    const Key& tag, const std::array<Projection, 4>& projections,
    const CoefficientMatrix& terminal, const RangeMatrix& range,
    std::span<const std::int64_t, 256> range_response);
Identifier constraint_identifier(std::span<const SparseEvaluation> evaluations);
std::vector<std::uint64_t> evaluate_constraints(std::span<const SparseEvaluation> evaluations,
                                               const SignedWitness& witness);
QPoly q_polynomial(const SignedPoly& polynomial);
QPoly q_involution(const QPoly& polynomial);

} // namespace blrs
