#include "blrs/relation.hpp"

#include <algorithm>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Public deterministic fixtures only. Never a signing random source.
class TestRandom final : public blrs::RandomSource {
public:
    void fill(std::span<std::uint8_t> bytes) override {
        for (auto& byte : bytes) byte = static_cast<std::uint8_t>(generator());
    }
private:
    std::mt19937_64 generator{65437};
};

bool satisfied(std::span<const blrs::SparseEvaluation> constraints, const blrs::SignedWitness& witness) {
    const auto residuals = blrs::evaluate_constraints(constraints, witness);
    return std::all_of(residuals.begin(), residuals.end(), [](auto value) { return value == 0; });
}

std::vector<std::uint64_t> direct_residuals(const blrs::StatementSetup& parameters, const blrs::Key& tag,
    const std::array<blrs::Projection, 4>& projections, const blrs::CoefficientMatrix& terminal,
    const blrs::RangeMatrix& range, const std::array<std::int64_t, 256>& response,
    const blrs::SignedWitness& witness) {
    using namespace blrs;
    auto mod = [](std::int64_t x, std::uint64_t q) {
        x %= static_cast<std::int64_t>(q);
        if (x < 0) x += static_cast<std::int64_t>(q);
        return static_cast<std::uint64_t>(x);
    };
    std::vector<std::uint64_t> result;
    auto append_field = [&](std::int64_t x) { result.push_back(mod(x, field_prime) * field_lift); };
    auto append_full = [&](std::int64_t x) { result.push_back(mod(x, proof_modulus)); };
    auto h = [&](std::size_t stage, std::size_t i) { return witness.message[1 + 3 * stage + i / degree][i % degree]; };
    const auto b = witness.message[0][0];
    Secret signed_secret{};
    for (std::size_t i = 0; i < secret_width; ++i)
        for (std::size_t j = 0; j < degree; ++j)
            signed_secret[i][j] = static_cast<std::uint16_t>(mod(witness.small[i][j], field_prime));
    const auto root = apply_matrix(parameters.key_matrix, signed_secret);
    const auto linked = apply_matrix(parameters.link_matrix, signed_secret);
    for (std::size_t stage = 0; stage < 4; ++stage)
        for (std::size_t row = 0; row < projection_rows; ++row) {
            std::int64_t value = 0;
            for (std::size_t digit = 0; digit < 8; ++digit)
                value += witness.small[18 + stage][digit] * h(stage, 8 * row + digit);
            for (std::size_t j = 0; j < projections[stage].columns; ++j) {
                const auto previous = stage == 0 ? static_cast<std::int64_t>(root[j / degree][j % degree]) : h(stage - 1, j);
                value -= b * projections[stage].coefficients[row * projections[stage].columns + j] * previous;
            }
            append_field(value);
        }
    for (std::size_t row = 0; row < 2; ++row)
        for (std::size_t j = 0; j < degree; ++j) append_field(linked[row][j] - b * tag[row][j]);
    for (std::size_t row = 0; row < 144; ++row) {
        std::int64_t value = -h(3, row);
        for (std::size_t j = 0; j < 16; ++j) value += terminal.coefficients[j * 144 + row] * witness.small[22][j];
        append_field(value);
    }
    for (std::size_t j = 1; j < degree; ++j) append_full(witness.message[0][j]);
    for (std::size_t stage = 0; stage < 5; ++stage)
        for (std::size_t j = radices[stage]; j < degree; ++j) append_field(witness.small[18 + stage][j]);
    for (std::size_t stage = 0; stage < 5; ++stage) {
        std::int64_t value = -b;
        for (std::size_t j = 0; j < radices[stage]; ++j) value += witness.small[18 + stage][j];
        append_field(value);
    }
    for (std::size_t stage = 0; stage < 4; ++stage)
        for (std::size_t j = 16; j < degree; ++j) append_full(witness.message[3 + 3 * stage][j]);
    std::array<std::int64_t, 1536> binary{};
    std::int64_t aggregate = 0;
    for (std::size_t i = 0; i < 1472; ++i) {
        const auto y = witness.small[i / degree][i % degree] - (b - 1) / 2;
        binary[i] = y;
        aggregate += y * (y - 1);
    }
    binary[1472] = (b + 1) / 2;
    aggregate += binary[1472] * (binary[1472] - 1);
    append_full(aggregate);
    for (std::size_t row = 0; row < 256; ++row) {
        std::int64_t value = witness.message[13 + row / degree][row % degree] - response[row];
        for (std::size_t j = 0; j < binary.size(); ++j) value += range[row * binary.size() + j] * binary[j];
        append_full(value);
    }
    return result;
}

void check_hash() {
    const std::array<std::uint8_t, 3> input{'a', 'b', 'c'};
    const auto bytes = blrs::shake256(input, 64);
    std::string hex;
    constexpr char digits[] = "0123456789abcdef";
    for (auto byte : bytes) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
    require(hex == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5"
                   "a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4", "SHAKE256 vector mismatch");
    const auto framed = blrs::frame("x", input);
    const blrs::Bytes expected{1, 0, 0, 0, 'x', 3, 0, 0, 0, 0, 0, 0, 0, 'a', 'b', 'c'};
    require(framed == expected, "frame encoding mismatch");
}

void check_negacyclic() {
    blrs::StatementSetup parameters{};
    blrs::Secret secret{};
    parameters.key_matrix[0][0][63] = 1;
    secret[0][1] = 1;
    const auto key = blrs::public_key(parameters, secret);
    require(key[0][0] == blrs::field_prime - 1, "X^64 must equal minus one");
    require(std::count(key[0].begin(), key[0].end(), 0) == 63, "unexpected negacyclic coefficient");
    require(blrs::index_digits(12345) == std::array<std::size_t, 5>{1, 4, 0, 3, 9}, "index12345 convention");
    require(blrs::index_digits(65535) == std::array<std::size_t, 5>{7, 7, 7, 7, 15}, "terminal index convention");
    bool threw = false;
    try { (void)blrs::index_digits(65536); } catch (const std::invalid_argument&) { threw = true; }
    require(threw, "out-of-range index accepted");
}

void check_full_relation() {
    using namespace blrs;
    TestRandom random;
    const auto parameters = setup(random);
    const auto secret = generate_secret(random);
    const auto key = public_key(parameters, secret);
    const auto tag = link_tag(parameters, secret);
    std::vector<Key> ring(ring_size);
    std::mt19937_64 fixture{18};
    for (auto& decoy : ring)
        for (auto& polynomial : decoy)
            for (auto& coefficient : polynomial)
                coefficient = static_cast<std::uint16_t>(fixture() % field_prime);
    constexpr std::size_t index = 12345;
    ring[index] = key;
    const Bytes context{'r', 'e', 'l', 'a', 't', 'i', 'o', 'n', '-', 't', 'e', 's', 't'};
    const auto statement_id = statement_identifier(parameters, context);
    const auto ring_id = ring_identifier(statement_id, ring);
    auto reordered = ring;
    std::swap(reordered[index], reordered[index + 1]);
    require(ring_identifier(statement_id, reordered) != ring_id, "ring order not hashed");

    std::array<Projection, 4> projections;
    std::array<std::array<std::uint16_t, 144>, 4> blocks{};
    auto prefix = frame("BLRS/test-fixture/v1", context);
    projections[0] = derive_projection(prefix, 0);
    auto table = fold_ring(ring, projections[0]);
    blocks[0] = witness_column(table, index, 1);
    for (unsigned stage = 1; stage < 4; ++stage) {
        append_u32(prefix, stage);
        projections[stage] = derive_projection(prefix, stage);
        table = fold_matrix(table, projections[stage]);
        blocks[stage] = witness_column(table, index, stage + 1);
    }
    require(table.rows == 144 && table.columns == 16, "incorrect fold dimensions");
    const auto range = derive_range_matrix(prefix);
    for (const int sign : {1, -1}) {
        auto witness = make_witness(secret, index, sign, blocks);
        require(check_semantic_relation(parameters, tag, projections, table, witness), "valid semantic relation rejected");
        const auto binary = binary_map(witness);
        auto response = project_binary(range, binary);
        std::size_t weight = 0;
        for (const auto& polynomial : binary)
            for (auto coefficient : polynomial) weight += static_cast<std::size_t>(coefficient);
        require(weight <= 1467, "binary weight exceeds bound");
        for (std::size_t row = 0; row < response.size(); ++row) {
            const auto mask = static_cast<std::int64_t>(row % 25) - 12;
            witness.message[13 + row / degree][row % degree] = mask;
            response[row] += mask;
        }
        const auto constraints = compile_evaluations(parameters, tag, projections, table, range, response);
        require(constraints.size() == 1133 && satisfied(constraints, witness), "valid compiled relation rejected");
        auto arbitrary = witness;
        for (auto& polynomial : arbitrary.small)
            for (auto& coefficient : polynomial) coefficient = static_cast<std::int64_t>(fixture() % 7) - 3;
        for (std::size_t i = 1; i < message_polynomials; ++i)
            for (auto& coefficient : arbitrary.message[i]) coefficient = static_cast<std::int64_t>(fixture() % 2049) - 1024;
        // The packed dot products use the separately constrained zero tails.
        for (std::size_t stage = 0; stage < 5; ++stage)
            std::fill(arbitrary.small[18 + stage].begin() + static_cast<std::ptrdiff_t>(radices[stage]),
                      arbitrary.small[18 + stage].end(), 0);
        for (std::size_t stage = 0; stage < 4; ++stage)
            std::fill(arbitrary.message[3 + 3 * stage].begin() + 16, arbitrary.message[3 + 3 * stage].end(), 0);
        require(evaluate_constraints(constraints, arbitrary) ==
                direct_residuals(parameters, tag, projections, table, range, response, arbitrary),
                "compiler differs from direct coefficient equations");
        const auto digest = constraint_identifier(constraints);
        auto mutated = witness;
        mutated.small[0][0] = 2;
        require(!satisfied(constraints, mutated), "nonbinary secret accepted");
        mutated = witness;
        mutated.message[0][1] = 1;
        require(!satisfied(constraints, mutated), "nonscalar sign accepted");
        mutated = witness;
        mutated.small[18][8] = sign;
        require(!satisfied(constraints, mutated), "selector tail accepted");
        mutated = witness;
        mutated.message[3][16] = field_prime;
        require(!satisfied(constraints, mutated), "full-Q packing tail became a modulo-p check");
        mutated = witness;
        mutated.message[13][0] += 1;
        require(!satisfied(constraints, mutated), "range opening mutation accepted");
        auto changed = response;
        changed[0] += 1;
        const auto changed_constraints = compile_evaluations(parameters, tag, projections, table, range, changed);
        require(!satisfied(changed_constraints, witness), "changed range response accepted");
        require(constraint_identifier(changed_constraints) != digest, "compiled statement not hashed");
        auto bad_tag = tag;
        bad_tag[0][0] = static_cast<std::uint16_t>((bad_tag[0][0] + 1) % field_prime);
        require(!check_semantic_relation(parameters, bad_tag, projections, table, witness), "changed tag accepted");
        require(!satisfied(compile_evaluations(parameters, bad_tag, projections, table, range, response), witness),
                "compiled changed tag accepted");
    }
    require(encode_keys(ring).size() == 16777216, "ring encoding is not 16 MiB");
}

} // namespace

int main() {
    try {
        check_hash();
        check_negacyclic();
        check_full_relation();
        std::cout << "PASS: SHAKE/frame vectors, negacyclic arithmetic, full 65536 ring, both signs, "
                     "1133 compiled evaluations and mutation checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
