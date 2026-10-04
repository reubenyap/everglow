#include "blrs/relation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace blrs {
namespace {

std::uint16_t field(std::int64_t value) {
    value %= field_prime;
    if (value < 0) value += field_prime;
    return static_cast<std::uint16_t>(value);
}

std::uint64_t residue(std::int64_t value) {
    value %= static_cast<std::int64_t>(proof_modulus);
    if (value < 0) value += static_cast<std::int64_t>(proof_modulus);
    return static_cast<std::uint64_t>(value);
}

bool binary_secret(const Secret& secret) {
    for (const auto& poly : secret)
        if (std::any_of(poly.begin(), poly.end(), [](auto c) { return c > 1; })) return false;
    return true;
}

void validate_statement(const StatementSetup& parameters) {
    for (const auto* matrix : {&parameters.key_matrix, &parameters.link_matrix})
        for (const auto& row : *matrix)
            for (const auto& poly : row)
                for (auto c : poly)
                    if (c >= field_prime) throw std::invalid_argument("noncanonical statement matrix");
}

void validate_projection(const Projection& projection, std::size_t columns) {
    if (projection.columns != columns || projection.coefficients.size() != projection_rows * columns ||
        std::any_of(projection.coefficients.begin(), projection.coefficients.end(),
                    [](auto c) { return c >= field_prime; }))
        throw std::invalid_argument("invalid projection matrix");
}

void validate_table(const CoefficientMatrix& table) {
    if (table.rows != 144 || table.columns == 0 || table.columns > ring_size ||
        table.coefficients.size() != table.rows * table.columns ||
        std::any_of(table.coefficients.begin(), table.coefficients.end(),
                    [](auto c) { return c >= field_prime; }))
        throw std::invalid_argument("invalid projected table");
}

std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    const auto sum = a + b; // Q < 2^60, so adding two residues cannot overflow.
    return sum >= proof_modulus ? sum - proof_modulus : sum;
}

std::uint64_t negate(std::uint64_t a) {
    return a == 0 ? 0 : proof_modulus - a;
}

std::uint64_t multiply(std::uint64_t a, std::uint64_t b) {
#if defined(__SIZEOF_INT128__)
    return static_cast<std::uint64_t>((static_cast<unsigned __int128>(a) * b) % proof_modulus);
#else
    // ponytail: portable diagnostic fallback; the benchmark toolchain has 128-bit integers.
    std::uint64_t result = 0;
    while (b != 0) {
        if ((b & 1) != 0) result = add(result, a);
        a = add(a, a);
        b >>= 1;
    }
    return result;
#endif
}

QPoly scaled(QPoly polynomial, std::uint64_t scalar) {
    for (auto& coefficient : polynomial) coefficient = multiply(coefficient, scalar);
    return polynomial;
}

QPoly monomial_inverse(std::size_t coefficient, std::uint64_t scalar = 1) {
    if (coefficient >= degree) throw std::invalid_argument("coefficient exceeds degree");
    QPoly polynomial{};
    polynomial[coefficient == 0 ? 0 : degree - coefficient] =
        coefficient == 0 ? scalar : negate(scalar);
    return polynomial;
}

QPoly q_multiply(const QPoly& left, const QPoly& right) {
    QPoly result{};
    for (std::size_t i = 0; i < degree; ++i) {
        if (left[i] == 0) continue;
        for (std::size_t j = 0; j < degree; ++j) {
            if (right[j] == 0) continue;
            auto value = multiply(left[i], right[j]);
            if (i + j >= degree) value = negate(value);
            result[(i + j) % degree] = add(result[(i + j) % degree], value);
        }
    }
    return result;
}

std::uint64_t constant_product(const QPoly& left, const QPoly& right) {
    auto result = multiply(left[0], right[0]);
    for (std::size_t i = 1; i < degree; ++i)
        result = add(result, negate(multiply(left[i], right[degree - i])));
    return result;
}

void add_polynomial(QPoly& into, const QPoly& from) {
    for (std::size_t i = 0; i < degree; ++i) into[i] = add(into[i], from[i]);
}

void linear(SparseEvaluation& evaluation, std::size_t index, const QPoly& coefficient) {
    if (index >= evaluation_variables) throw std::invalid_argument("linear variable exceeds layout");
    const auto term = std::find_if(evaluation.linear.begin(), evaluation.linear.end(),
                                  [index](const auto& value) { return value.index == index; });
    if (term == evaluation.linear.end()) evaluation.linear.push_back({index, coefficient});
    else add_polynomial(term->coefficient, coefficient);
}

void quadratic(SparseEvaluation& evaluation, std::size_t left, std::size_t right,
               const QPoly& coefficient) {
    if (left > right) std::swap(left, right);
    if (right >= evaluation_variables) throw std::invalid_argument("quadratic variable exceeds layout");
    const auto term = std::find_if(evaluation.quadratic.begin(), evaluation.quadratic.end(),
        [left, right](const auto& value) { return value.left == left && value.right == right; });
    if (term == evaluation.quadratic.end()) evaluation.quadratic.push_back({left, right, coefficient});
    else add_polynomial(term->coefficient, coefficient);
}

constexpr std::size_t p_variable(std::size_t polynomial) { return 2 * polynomial; }
constexpr std::size_t m_variable(std::size_t polynomial) { return 2 * (small_polynomials + polynomial); }
constexpr std::size_t b_variable = m_variable(0);

QPoly coefficient_dot(std::span<const std::uint16_t> coefficients) {
    QPoly result{};
    for (std::size_t i = 0; i < coefficients.size(); ++i)
        add_polynomial(result, monomial_inverse(i, coefficients[i]));
    return result;
}

QPoly field_polynomial(const FieldPoly& polynomial) {
    QPoly result{};
    std::copy(polynomial.begin(), polynomial.end(), result.begin());
    return result;
}

void lift(SparseEvaluation& evaluation) {
    for (auto& term : evaluation.linear) term.coefficient = scaled(term.coefficient, field_lift);
    for (auto& term : evaluation.quadratic) term.coefficient = scaled(term.coefficient, field_lift);
    evaluation.constant = scaled(evaluation.constant, field_lift);
}

std::uint16_t flattened(const Key& key, std::size_t row) {
    return key[row / degree][row % degree];
}

void append_qpoly(Bytes& bytes, const QPoly& polynomial) {
    for (auto coefficient : polynomial) {
        if (coefficient >= proof_modulus) throw std::invalid_argument("noncanonical Q coefficient");
        append_u64(bytes, coefficient);
    }
}

} // namespace

StatementSetup setup(RandomSource& random) {
    StatementSetup parameters;
    std::array<std::uint8_t, 4096> bytes{};
    std::size_t next = bytes.size();
    auto sample = [&] {
        for (;;) {
            if (next == bytes.size()) { random.fill(bytes); next = 0; }
            const auto value = static_cast<std::uint16_t>(bytes[next] |
                               (static_cast<unsigned>(bytes[next + 1]) << 8));
            next += 2;
            if (value < field_prime) return value;
        }
    };
    for (auto* matrix : {&parameters.key_matrix, &parameters.link_matrix})
        for (auto& row : *matrix)
            for (auto& poly : row)
                for (auto& coefficient : poly) coefficient = sample();
    return parameters;
}

Secret generate_secret(RandomSource& random) {
    std::array<std::uint8_t, secret_width * degree / 8> bytes{};
    random.fill(bytes);
    Secret secret{};
    for (std::size_t i = 0; i < secret_width * degree; ++i)
        secret[i / degree][i % degree] = static_cast<std::uint16_t>((bytes[i / 8] >> (i % 8)) & 1);
    return secret;
}

Key apply_matrix(const StatementMatrix& matrix, const Secret& secret) {
    Key key{};
    for (const auto& poly : secret)
        for (auto coefficient : poly)
            if (coefficient >= field_prime) throw std::invalid_argument("noncanonical matrix input");
    for (std::size_t row = 0; row < key.size(); ++row) {
        std::array<std::int64_t, degree> output{};
        for (std::size_t column = 0; column < secret_width; ++column)
            for (std::size_t i = 0; i < degree; ++i) {
                const auto coefficient = matrix[row][column][i];
                if (coefficient >= field_prime) throw std::invalid_argument("noncanonical matrix coefficient");
                for (std::size_t j = 0; j < degree; ++j) {
                    const auto value = static_cast<std::int64_t>(coefficient) * secret[column][j];
                    output[(i + j) % degree] += i + j < degree ? value : -value;
                }
            }
        for (std::size_t i = 0; i < degree; ++i) key[row][i] = field(output[i]);
    }
    return key;
}

Key public_key(const StatementSetup& parameters, const Secret& secret) {
    if (!binary_secret(secret)) throw std::invalid_argument("secret is not binary");
    return apply_matrix(parameters.key_matrix, secret);
}

Key link_tag(const StatementSetup& parameters, const Secret& secret) {
    if (!binary_secret(secret)) throw std::invalid_argument("secret is not binary");
    return apply_matrix(parameters.link_matrix, secret);
}

bool canonical_key(const Key& key) {
    for (const auto& poly : key)
        if (std::any_of(poly.begin(), poly.end(), [](auto c) { return c >= field_prime; })) return false;
    return true;
}

std::array<std::size_t, 5> index_digits(std::size_t index) {
    if (index >= ring_size) throw std::invalid_argument("ring index out of range");
    std::array<std::size_t, 5> digits{};
    for (std::size_t j = radices.size(); j-- != 0;) { digits[j] = index % radices[j]; index /= radices[j]; }
    return digits;
}

std::span<const std::uint16_t> CoefficientMatrix::column(std::size_t index) const {
    if (rows != 144 || columns == 0 || columns > ring_size || coefficients.size() != rows * columns ||
        index >= columns) throw std::invalid_argument("invalid projected column");
    return {coefficients.data() + index * rows, rows};
}

Projection derive_projection(std::span<const std::uint8_t> prefix, unsigned stage) {
    if (stage >= 4) throw std::invalid_argument("fold stage out of range");
    Projection projection;
    projection.columns = stage == 0 ? 128 : 144;
    const auto count = projection_rows * projection.columns;
    const auto input = frame("BLRS/fold/" + std::to_string(stage) + "/v1", prefix);
    // Recompute a longer prefix only if rejection exhausts the initial stream.
    std::size_t length = 2 * count + 128;
    for (;;) {
        const auto bytes = shake256(input, length);
        projection.coefficients.clear();
        projection.coefficients.reserve(count);
        for (std::size_t i = 0; i + 1 < bytes.size() && projection.coefficients.size() < count; i += 2) {
            const auto value = static_cast<std::uint16_t>(bytes[i] |
                               (static_cast<unsigned>(bytes[i + 1]) << 8));
            if (value < field_prime) projection.coefficients.push_back(value);
        }
        if (projection.coefficients.size() == count) return projection;
        if (length > 1U << 24) throw std::runtime_error("projection XOF resource limit");
        length *= 2;
    }
}

CoefficientMatrix fold_ring(std::span<const Key> ring, const Projection& projection) {
    if (ring.size() != ring_size) throw std::invalid_argument("ring must contain 65536 keys");
    validate_projection(projection, 128);
    if (!std::all_of(ring.begin(), ring.end(), canonical_key))
        throw std::invalid_argument("noncanonical ring key");
    CoefficientMatrix result{144, ring_size / 8, std::vector<std::uint16_t>(144 * (ring_size / 8))};
    for (std::size_t c = 0; c < result.columns; ++c)
        for (std::size_t k = 0; k < 8; ++k) {
            const auto& key = ring[k * result.columns + c];
            for (std::size_t a = 0; a < projection_rows; ++a) {
                std::uint64_t sum = 0;
                for (std::size_t j = 0; j < 128; ++j)
                    sum += static_cast<std::uint64_t>(projection.coefficients[a * 128 + j]) * flattened(key, j);
                result.coefficients[c * 144 + 8 * a + k] = static_cast<std::uint16_t>(sum % field_prime);
            }
        }
    return result;
}

CoefficientMatrix fold_matrix(const CoefficientMatrix& table, const Projection& projection) {
    validate_table(table);
    validate_projection(projection, table.rows);
    if (table.columns % 8 != 0) throw std::invalid_argument("fold input is not divisible by eight");
    CoefficientMatrix result{144, table.columns / 8,
                             std::vector<std::uint16_t>(144 * (table.columns / 8))};
    for (std::size_t c = 0; c < result.columns; ++c)
        for (std::size_t k = 0; k < 8; ++k) {
            const auto column = table.column(k * result.columns + c);
            for (std::size_t a = 0; a < projection_rows; ++a) {
                std::uint64_t sum = 0;
                for (std::size_t j = 0; j < table.rows; ++j)
                    sum += static_cast<std::uint64_t>(projection.coefficients[a * table.rows + j]) * column[j];
                result.coefficients[c * 144 + 8 * a + k] = static_cast<std::uint16_t>(sum % field_prime);
            }
        }
    return result;
}

std::array<std::uint16_t, 144> witness_column(const CoefficientMatrix& table,
                                             std::size_t original_index, unsigned completed_folds) {
    if (original_index >= ring_size || completed_folds == 0 || completed_folds > 4)
        throw std::invalid_argument("invalid witness stage");
    std::size_t count = ring_size;
    for (unsigned j = 0; j < completed_folds; ++j) count /= 8;
    if (table.columns != count) throw std::invalid_argument("wrong witness table stage");
    const auto column = table.column(original_index % count);
    std::array<std::uint16_t, 144> result{};
    std::copy(column.begin(), column.end(), result.begin());
    return result;
}

SignedWitness make_witness(const Secret& secret, std::size_t index, int sign,
                           const std::array<std::array<std::uint16_t, 144>, 4>& blocks) {
    if (!binary_secret(secret) || (sign != 1 && sign != -1))
        throw std::invalid_argument("invalid signed witness input");
    const auto digits = index_digits(index);
    SignedWitness witness{};
    witness.message[0][0] = sign;
    for (std::size_t i = 0; i < secret_width; ++i)
        for (std::size_t j = 0; j < degree; ++j) witness.small[i][j] = sign * secret[i][j];
    for (std::size_t j = 0; j < digits.size(); ++j) witness.small[secret_width + j][digits[j]] = sign;
    for (std::size_t stage = 0; stage < 4; ++stage)
        for (std::size_t i = 0; i < 144; ++i) {
            if (blocks[stage][i] >= field_prime) throw std::invalid_argument("noncanonical witness block");
            witness.message[1 + 3 * stage + i / degree][i % degree] = sign * blocks[stage][i];
        }
    return witness;
}

BinaryWitness binary_map(const SignedWitness& witness) {
    const auto b = witness.message[0][0];
    if ((b != 1 && b != -1) ||
        std::any_of(witness.message[0].begin() + 1, witness.message[0].end(), [](auto c) { return c != 0; }))
        throw std::invalid_argument("binary map requires integer scalar global sign");
    BinaryWitness binary{};
    for (std::size_t i = 0; i < small_polynomials; ++i)
        for (std::size_t j = 0; j < degree; ++j) {
            if (witness.small[i][j] != 0 && witness.small[i][j] != b)
                throw std::invalid_argument("binary map input is not signed binary");
            binary[i][j] = witness.small[i][j] - (b - 1) / 2;
        }
    binary[23][0] = (b + 1) / 2;
    return binary;
}

bool check_semantic_relation(const StatementSetup& parameters, const Key& tag,
                             const std::array<Projection, 4>& projections,
                             const CoefficientMatrix& terminal, const SignedWitness& witness) {
    try {
        validate_statement(parameters);
        if (!canonical_key(tag) || terminal.columns != 16) return false;
        validate_table(terminal);
        for (std::size_t stage = 0; stage < 4; ++stage)
            validate_projection(projections[stage], stage == 0 ? 128 : 144);
        const auto b = witness.message[0][0];
        if ((b != 1 && b != -1) ||
            std::any_of(witness.message[0].begin() + 1, witness.message[0].end(), [](auto c) { return c != 0; }))
            return false;
        for (const auto& polynomial : witness.small)
            for (auto c : polynomial) if (c != 0 && c != b) return false;
        for (std::size_t stage = 0; stage < 5; ++stage) {
            const auto& selector = witness.small[18 + stage];
            if (std::any_of(selector.begin() + static_cast<std::ptrdiff_t>(radices[stage]), selector.end(),
                            [](auto c) { return c != 0; })) return false;
            std::int64_t sum = 0;
            for (std::size_t i = 0; i < radices[stage]; ++i) sum += selector[i];
            if (sum != b) return false;
        }
        for (std::size_t stage = 0; stage < 4; ++stage)
            if (std::any_of(witness.message[3 + 3 * stage].begin() + 16,
                            witness.message[3 + 3 * stage].end(), [](auto c) { return c != 0; })) return false;
        Secret signed_secret{};
        for (std::size_t i = 0; i < secret_width; ++i)
            for (std::size_t j = 0; j < degree; ++j) signed_secret[i][j] = field(witness.small[i][j]);
        const auto root = apply_matrix(parameters.key_matrix, signed_secret);
        const auto linked = apply_matrix(parameters.link_matrix, signed_secret);
        for (std::size_t i = 0; i < 128; ++i)
            if (flattened(linked, i) != field(b * flattened(tag, i))) return false;
        for (std::size_t stage = 0; stage < 4; ++stage) {
            for (std::size_t a = 0; a < projection_rows; ++a) {
                std::int64_t lhs = 0, rhs = 0;
                for (std::size_t k = 0; k < 8; ++k) {
                    const auto index = 8 * a + k;
                    lhs += witness.small[18 + stage][k] * field(witness.message[1 + 3 * stage + index / degree][index % degree]);
                }
                for (std::size_t j = 0; j < projections[stage].columns; ++j) {
                    const auto previous = stage == 0 ? flattened(root, j) :
                        field(witness.message[1 + 3 * (stage - 1) + j / degree][j % degree]);
                    rhs += static_cast<std::int64_t>(projections[stage].coefficients[a * projections[stage].columns + j]) * previous;
                }
                if (field(lhs) != field(b * rhs)) return false;
            }
        }
        for (std::size_t row = 0; row < 144; ++row) {
            std::int64_t sum = 0;
            for (std::size_t k = 0; k < 16; ++k)
                sum += terminal.coefficients[k * 144 + row] * witness.small[22][k];
            if (field(sum) != field(witness.message[10 + row / degree][row % degree])) return false;
        }
        return true;
    } catch (const std::invalid_argument&) { return false; }
}

Bytes encode_key(const Key& key) {
    if (!canonical_key(key)) throw std::invalid_argument("noncanonical key encoding");
    Bytes bytes;
    bytes.reserve(256);
    for (const auto& polynomial : key) for (auto coefficient : polynomial) append_u16(bytes, coefficient);
    return bytes;
}

Bytes encode_keys(std::span<const Key> keys) {
    if (keys.size() > std::numeric_limits<std::size_t>::max() / 256)
        throw std::invalid_argument("key encoding too large");
    Bytes bytes;
    bytes.reserve(keys.size() * 256);
    for (const auto& key : keys) {
        if (!canonical_key(key)) throw std::invalid_argument("noncanonical key encoding");
        for (const auto& polynomial : key) for (auto coefficient : polynomial) append_u16(bytes, coefficient);
    }
    return bytes;
}

Bytes encode_q_polynomials(std::span<const QPoly> polynomials) {
    Bytes bytes;
    if (polynomials.size() > std::numeric_limits<std::size_t>::max() / (degree * 8))
        throw std::invalid_argument("Q encoding too large");
    bytes.reserve(polynomials.size() * degree * 8);
    for (const auto& polynomial : polynomials) append_qpoly(bytes, polynomial);
    return bytes;
}

Bytes encode_signed_coefficients(std::span<const std::int64_t> coefficients) {
    Bytes bytes;
    if (coefficients.size() > std::numeric_limits<std::size_t>::max() / 8)
        throw std::invalid_argument("signed encoding too large");
    bytes.reserve(coefficients.size() * 8);
    for (auto coefficient : coefficients) append_u64(bytes, static_cast<std::uint64_t>(coefficient));
    return bytes;
}

Identifier statement_identifier(const StatementSetup& parameters, std::span<const std::uint8_t> context) {
    validate_statement(parameters);
    Bytes bytes;
    append_u32(bytes, field_prime);
    append_u16(bytes, degree);
    append_u16(bytes, secret_width);
    for (const auto* matrix : {&parameters.key_matrix, &parameters.link_matrix})
        for (const auto& row : *matrix)
            for (const auto& polynomial : row)
                for (auto coefficient : polynomial) append_u16(bytes, coefficient);
    append_u64(bytes, context.size());
    bytes.insert(bytes.end(), context.begin(), context.end());
    return framed_identifier("BLRS/statement/v1", bytes);
}

Identifier ring_identifier(const Identifier& statement_id, std::span<const Key> ring) {
    if (ring.size() != ring_size) throw std::invalid_argument("ring identifier requires 65536 keys");
    Bytes bytes(statement_id.begin(), statement_id.end());
    append_u32(bytes, static_cast<std::uint32_t>(ring.size()));
    const auto keys = encode_keys(ring);
    bytes.insert(bytes.end(), keys.begin(), keys.end());
    return framed_identifier("BLRS/ring/v1", bytes);
}

RangeMatrix derive_range_matrix(std::span<const std::uint8_t> prefix) {
    constexpr std::size_t entries = 256 * 24 * degree;
    const auto bytes = shake256(frame("BLRS/range/v1", prefix), entries / 4);
    RangeMatrix projection(entries);
    for (std::size_t i = 0; i < entries; ++i) {
        const auto bits = bytes[i / 4] >> (2 * (i % 4));
        projection[i] = static_cast<std::int8_t>(static_cast<int>(bits & 1) - static_cast<int>((bits >> 1) & 1));
    }
    return projection;
}

std::array<std::int64_t, 256> project_binary(const RangeMatrix& projection, const BinaryWitness& binary) {
    if (projection.size() != 256 * 24 * degree) throw std::invalid_argument("invalid range projection size");
    for (const auto& polynomial : binary)
        for (auto c : polynomial) if (c != 0 && c != 1) throw std::invalid_argument("nonbinary projection input");
    std::array<std::int64_t, 256> result{};
    for (std::size_t row = 0; row < result.size(); ++row)
        for (std::size_t i = 0; i < 24 * degree; ++i) {
            const auto coefficient = projection[row * 24 * degree + i];
            if (coefficient < -1 || coefficient > 1) throw std::invalid_argument("invalid ternary projection");
            result[row] += coefficient * binary[i / degree][i % degree];
        }
    return result;
}

QPoly q_polynomial(const SignedPoly& polynomial) {
    QPoly result{};
    for (std::size_t i = 0; i < degree; ++i) result[i] = residue(polynomial[i]);
    return result;
}

QPoly q_involution(const QPoly& polynomial) {
    if (std::any_of(polynomial.begin(), polynomial.end(), [](auto c) { return c >= proof_modulus; }))
        throw std::invalid_argument("noncanonical involution input");
    QPoly result{};
    result[0] = polynomial[0];
    for (std::size_t i = 1; i < degree; ++i) result[i] = negate(polynomial[degree - i]);
    return result;
}

std::vector<SparseEvaluation> compile_evaluations(const StatementSetup& parameters,
    const Key& tag, const std::array<Projection, 4>& projections,
    const CoefficientMatrix& terminal, const RangeMatrix& range,
    std::span<const std::int64_t, 256> range_response) {
    validate_statement(parameters);
    if (!canonical_key(tag)) throw std::invalid_argument("noncanonical tag");
    validate_table(terminal);
    if (terminal.columns != 16) throw std::invalid_argument("terminal table must have 16 columns");
    for (std::size_t stage = 0; stage < 4; ++stage)
        validate_projection(projections[stage], stage == 0 ? 128 : 144);
    if (range.size() != 256 * 24 * degree ||
        std::any_of(range.begin(), range.end(), [](auto c) { return c < -1 || c > 1; }))
        throw std::invalid_argument("invalid range matrix");
    if (std::any_of(range_response.begin(), range_response.end(), [](auto c) {
            return c < -range_response_cap || c > range_response_cap;
        })) throw std::invalid_argument("range response exceeds infinity cap");

    std::vector<SparseEvaluation> evaluations;
    evaluations.reserve(scalar_evaluations);
    // The four recursive field equalities.
    for (std::size_t stage = 0; stage < 4; ++stage) {
        const auto& projection = projections[stage];
        for (std::size_t a = 0; a < projection_rows; ++a) {
            SparseEvaluation evaluation;
            const auto offset = 8 * a;
            quadratic(evaluation, p_variable(18 + stage) + 1,
                      m_variable(1 + 3 * stage + offset / degree), monomial_inverse(offset % degree));
            if (stage == 0) {
                std::array<QPoly, 2> projected_rows{};
                for (std::size_t row = 0; row < 2; ++row)
                    projected_rows[row] = coefficient_dot(std::span(projection.coefficients)
                        .subspan(a * 128 + row * degree, degree));
                for (std::size_t column = 0; column < secret_width; ++column) {
                    QPoly coefficient{};
                    for (std::size_t row = 0; row < 2; ++row)
                        add_polynomial(coefficient, q_multiply(projected_rows[row],
                                                              field_polynomial(parameters.key_matrix[row][column])));
                    quadratic(evaluation, b_variable, p_variable(column), scaled(coefficient, proof_modulus - 1));
                }
            } else {
                for (std::size_t block = 0; block < 3; ++block) {
                    const auto count = block == 2 ? 16U : 64U;
                    const auto coefficient = coefficient_dot(std::span(projection.coefficients)
                        .subspan(a * 144 + block * degree, count));
                    quadratic(evaluation, b_variable, m_variable(1 + 3 * (stage - 1) + block),
                              scaled(coefficient, proof_modulus - 1));
                }
            }
            lift(evaluation);
            evaluations.push_back(std::move(evaluation));
        }
    }
    // Exact tag equality and final membership are linear field relations.
    for (std::size_t row = 0; row < 2; ++row)
        for (std::size_t coefficient = 0; coefficient < degree; ++coefficient) {
            SparseEvaluation evaluation;
            for (std::size_t column = 0; column < secret_width; ++column)
                linear(evaluation, p_variable(column), q_multiply(monomial_inverse(coefficient),
                       field_polynomial(parameters.link_matrix[row][column])));
            linear(evaluation, b_variable, monomial_inverse(0, negate(tag[row][coefficient])));
            lift(evaluation);
            evaluations.push_back(std::move(evaluation));
        }
    for (std::size_t row = 0; row < 144; ++row) {
        SparseEvaluation evaluation;
        QPoly coefficient{};
        for (std::size_t column = 0; column < 16; ++column)
            add_polynomial(coefficient, monomial_inverse(column, terminal.coefficients[column * 144 + row]));
        linear(evaluation, p_variable(22), coefficient);
        linear(evaluation, m_variable(10 + row / degree), monomial_inverse(row % degree, proof_modulus - 1));
        lift(evaluation);
        evaluations.push_back(std::move(evaluation));
    }
    // Scalarity of b is a full-Q condition.
    for (std::size_t coefficient = 1; coefficient < degree; ++coefficient) {
        SparseEvaluation evaluation;
        linear(evaluation, b_variable, monomial_inverse(coefficient));
        evaluations.push_back(std::move(evaluation));
    }
    for (std::size_t stage = 0; stage < 5; ++stage) {
        for (std::size_t coefficient = radices[stage]; coefficient < degree; ++coefficient) {
            SparseEvaluation evaluation;
            linear(evaluation, p_variable(18 + stage), monomial_inverse(coefficient));
            lift(evaluation);
            evaluations.push_back(std::move(evaluation));
        }
    }
    for (std::size_t stage = 0; stage < 5; ++stage) {
        SparseEvaluation evaluation;
        QPoly coefficient{};
        for (std::size_t i = 0; i < radices[stage]; ++i)
            add_polynomial(coefficient, monomial_inverse(i));
        linear(evaluation, p_variable(18 + stage), coefficient);
        linear(evaluation, b_variable, monomial_inverse(0, proof_modulus - 1));
        lift(evaluation);
        evaluations.push_back(std::move(evaluation));
    }
    // Literal h packing tails are full-Q zeros, not field equalities.
    for (std::size_t stage = 0; stage < 4; ++stage)
        for (std::size_t coefficient = 16; coefficient < degree; ++coefficient) {
            SparseEvaluation evaluation;
            linear(evaluation, m_variable(3 + 3 * stage), monomial_inverse(coefficient));
            evaluations.push_back(std::move(evaluation));
        }
    if (evaluations.size() != 876) throw std::logic_error("external constraint inventory mismatch");

    // Under the separately enforced scalarity of b, sum Y_i(Y_i-1) expands to
    // sum P_i^2 - b*sum P_i + (1473/4)*(b^2-1).
    SparseEvaluation binary;
    QPoly coefficient_sum{};
    for (std::size_t i = 0; i < degree; ++i)
        add_polynomial(coefficient_sum, monomial_inverse(i, proof_modulus - 1));
    for (std::size_t polynomial = 0; polynomial < small_polynomials; ++polynomial) {
        quadratic(binary, p_variable(polynomial), p_variable(polynomial) + 1, monomial_inverse(0));
        quadratic(binary, p_variable(polynomial), b_variable, coefficient_sum);
    }
    const auto inverse_two = (proof_modulus + 1) / 2;
    const auto sign_scalar = multiply(1473, multiply(inverse_two, inverse_two));
    quadratic(binary, b_variable, b_variable, monomial_inverse(0, sign_scalar));
    binary.constant[0] = negate(sign_scalar);
    evaluations.push_back(std::move(binary));

    // Range openings use the same affine map. The 63 sign tails are zero by
    // scalarity, so only the first entry of the final binary polynomial enters.
    for (std::size_t row = 0; row < 256; ++row) {
        SparseEvaluation evaluation;
        const auto start = row * 24 * degree;
        std::int64_t sum = 0;
        for (std::size_t polynomial = 0; polynomial < small_polynomials; ++polynomial) {
            QPoly coefficient{};
            for (std::size_t i = 0; i < degree; ++i) {
                const auto value = range[start + polynomial * degree + i];
                sum += value;
                add_polynomial(coefficient, monomial_inverse(i, residue(value)));
            }
            linear(evaluation, p_variable(polynomial), coefficient);
        }
        const auto sign_entry = range[start + 23 * degree];
        linear(evaluation, b_variable, monomial_inverse(0,
               multiply(residue(sign_entry - sum), inverse_two)));
        linear(evaluation, m_variable(13 + row / degree), monomial_inverse(row % degree));
        evaluation.constant[0] = add(multiply(residue(sum + sign_entry), inverse_two),
                                      negate(residue(range_response[row])));
        evaluations.push_back(std::move(evaluation));
    }
    for (auto& evaluation : evaluations) {
        std::sort(evaluation.linear.begin(), evaluation.linear.end(),
                  [](const auto& left, const auto& right) { return left.index < right.index; });
        std::sort(evaluation.quadratic.begin(), evaluation.quadratic.end(), [](const auto& left, const auto& right) {
            return left.left != right.left ? left.left < right.left : left.right < right.right;
        });
    }
    if (evaluations.size() != scalar_evaluations) throw std::logic_error("complete constraint inventory mismatch");
    return evaluations;
}

Identifier constraint_identifier(std::span<const SparseEvaluation> evaluations) {
    if (evaluations.size() != scalar_evaluations) throw std::invalid_argument("constraint inventory mismatch");
    Bytes bytes;
    // Fixed schema, dimensions and canonical sparse order are hashed as well as coefficients.
    append_u16(bytes, 1);
    append_u16(bytes, evaluation_variables);
    append_u32(bytes, scalar_evaluations);
    for (const auto& evaluation : evaluations) {
        append_u32(bytes, static_cast<std::uint32_t>(evaluation.quadratic.size()));
        std::size_t previous = 0;
        bool first = true;
        for (const auto& term : evaluation.quadratic) {
            if (term.left > term.right || term.right >= evaluation_variables)
                throw std::invalid_argument("invalid quadratic constraint index");
            const auto index = term.left * evaluation_variables + term.right;
            if (!first && index <= previous) throw std::invalid_argument("noncanonical quadratic constraint order");
            first = false;
            previous = index;
            append_u16(bytes, static_cast<std::uint16_t>(term.left));
            append_u16(bytes, static_cast<std::uint16_t>(term.right));
            append_qpoly(bytes, term.coefficient);
        }
        append_u32(bytes, static_cast<std::uint32_t>(evaluation.linear.size()));
        first = true;
        for (const auto& term : evaluation.linear) {
            if (term.index >= evaluation_variables || (!first && term.index <= previous))
                throw std::invalid_argument("noncanonical linear constraint order");
            first = false;
            previous = term.index;
            append_u16(bytes, static_cast<std::uint16_t>(term.index));
            append_qpoly(bytes, term.coefficient);
        }
        append_qpoly(bytes, evaluation.constant);
    }
    return framed_identifier("BLRS/compiled/v1", bytes);
}

std::vector<std::uint64_t> evaluate_constraints(std::span<const SparseEvaluation> evaluations,
                                                const SignedWitness& witness) {
    std::array<QPoly, evaluation_variables> variables{};
    for (std::size_t i = 0; i < small_polynomials + message_polynomials; ++i) {
        const auto polynomial = i < small_polynomials ? q_polynomial(witness.small[i]) :
                                q_polynomial(witness.message[i - small_polynomials]);
        variables[2 * i] = polynomial;
        variables[2 * i + 1] = q_involution(polynomial);
    }
    std::vector<std::uint64_t> result;
    result.reserve(evaluations.size());
    for (const auto& evaluation : evaluations) {
        auto value = evaluation.constant[0];
        if (value >= proof_modulus) throw std::invalid_argument("noncanonical constraint constant");
        for (const auto& term : evaluation.linear) {
            if (term.index >= evaluation_variables) throw std::invalid_argument("invalid linear constraint index");
            if (std::any_of(term.coefficient.begin(), term.coefficient.end(), [](auto c) { return c >= proof_modulus; }))
                throw std::invalid_argument("noncanonical linear constraint coefficient");
            value = add(value, constant_product(term.coefficient, variables[term.index]));
        }
        for (const auto& term : evaluation.quadratic) {
            if (term.left > term.right || term.right >= evaluation_variables)
                throw std::invalid_argument("invalid quadratic constraint index");
            if (std::any_of(term.coefficient.begin(), term.coefficient.end(), [](auto c) { return c >= proof_modulus; }))
                throw std::invalid_argument("noncanonical quadratic constraint coefficient");
            value = add(value, constant_product(term.coefficient,
                        q_multiply(variables[term.left], variables[term.right])));
        }
        result.push_back(value);
    }
    return result;
}

} // namespace blrs
