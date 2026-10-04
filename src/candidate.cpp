#include "blrs/candidate.hpp"
#include "build_identity.hpp"

#include <algorithm>
#include <bit>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace blrs {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::int64_t range_cap = 9751757;

double elapsed(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

struct Reader {
    std::span<const std::uint8_t> bytes;
    std::size_t offset = 0;
    std::span<const std::uint8_t> take(std::size_t count) {
        if (count > bytes.size() - offset) throw std::invalid_argument("truncated encoding");
        const auto value = bytes.subspan(offset, count);
        offset += count;
        return value;
    }
    std::uint64_t integer(unsigned count) {
        std::uint64_t result = 0;
        auto value = take(count);
        for (unsigned i = 0; i < count; ++i) result |= std::uint64_t(value[i]) << (8U*i);
        return result;
    }
    void magic(std::string_view expected) {
        const auto value = take(expected.size());
        if (!std::equal(value.begin(), value.end(), expected.begin()))
            throw std::invalid_argument("unknown encoding");
    }
};

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size()*2);
    for (auto x : bytes) { result += digits[x >> 4]; result += digits[x & 15]; }
    return result;
}

void validate_crs(const ProofCrs& crs) {
    if (crs.A1.size() != 20*23 || crs.A2prime.size() != 20*75 || crs.Bprime.size() != 23*75)
        throw std::invalid_argument("wrong CRS dimensions");
    for (const auto* matrix : {&crs.A1, &crs.A2prime, &crs.Bprime})
        for (const auto& poly : *matrix)
            for (const auto coefficient : poly)
                if (coefficient >= proof_modulus) throw std::invalid_argument("noncanonical CRS");
}

void validate_signature(const ResearchSignature& sig, CoreProfile profile) {
    if (!canonical_key(sig.tag)) throw std::invalid_argument("noncanonical tag");
    validate_proof_body(sig.base, sig.range_response, profile);
}

Bytes initial_prefix(const ResearchSignature& sig, std::span<const std::uint8_t> message) {
    Bytes prefix, version;
    append_u16(version, 1);
    append_frame(prefix, "BLRS/version/v1", version);
    append_frame(prefix, "BLRS/statement-id/v1", sig.statement_id);
    append_frame(prefix, "BLRS/proof-id/v1", sig.proof_id);
    append_frame(prefix, "BLRS/ring-id/v1", sig.ring_id);
    append_frame(prefix, "BLRS/message/v1", message);
    append_frame(prefix, "BLRS/tag/v1", encode_key(sig.tag));
    append_frame(prefix, "BLRS/CA/v1", encode_q_polynomials(sig.base.tA1));
    append_frame(prefix, "BLRS/Cb/v1", encode_q_polynomials(std::span(sig.base.tB).first(1)));
    return prefix;
}

void append_h(Bytes& prefix, unsigned stage, std::span<const QPoly> tB) {
    append_frame(prefix, "BLRS/h-commit/" + std::to_string(stage+1) + "/v1",
                 encode_q_polynomials(tB.subspan(1+3*stage, 3)));
}

Seed base_seed(Bytes prefix, std::span<const SparseEvaluation> equations) {
    auto value = frame("BLRS/base/v1", prefix);
    append_frame(value, "BLRS/constraints/v1", constraint_identifier(equations));
    const auto bytes = shake256(value, 32);
    Seed seed{};
    std::copy(bytes.begin(), bytes.end(), seed.begin());
    return seed;
}

void fill_rho(Opening& opening, RandomSource& random) {
    std::array<std::uint8_t, 8192> bytes{};
    std::size_t position = bytes.size();
    for (auto& poly : opening.rho) for (auto& coefficient : poly) {
        std::uint8_t value;
        do {
            if (position == bytes.size()) { random.fill(bytes); position = 0; }
            value = bytes[position++];
        } while (value == 255);
        coefficient = int(value % 3) - 1;
    }
}
} // namespace

CandidateParameters generate_parameters(RandomSource& random, Bytes context) {
    CandidateParameters parameters{setup(random), {}, std::move(context)};
    parameters.crs.A1.resize(20*23);
    parameters.crs.A2prime.resize(20*75);
    parameters.crs.Bprime.resize(23*75);
    std::array<std::uint8_t, 8192> buffer{};
    std::size_t position = buffer.size();
    for (auto* matrix : {&parameters.crs.A1, &parameters.crs.A2prime, &parameters.crs.Bprime}) {
        for (auto& poly : *matrix) for (auto& coefficient : poly) {
            std::uint64_t value;
            do {
                if (position == buffer.size()) { random.fill(buffer); position = 0; }
                value = 0;
                for (unsigned k = 0; k < 8; ++k) value |= std::uint64_t(buffer[position++]) << (8U*k);
                value &= (std::uint64_t(1) << 60) - 1;
            } while (value >= proof_modulus);
            coefficient = value;
        }
    }
    return parameters;
}

Bytes encode_crs(const ProofCrs& crs) {
    validate_crs(crs);
    Bytes bytes{'B','L','R','S','C','R','0','1'};
    bytes.reserve(1886764);
    append_u16(bytes, 1); append_u64(bytes, proof_modulus); append_u16(bytes, 64);
    for (const auto [matrix, rows, columns] : {
        std::tuple{&crs.A1, 20U, 23U}, std::tuple{&crs.A2prime, 20U, 75U},
        std::tuple{&crs.Bprime, 23U, 75U}}) {
        append_u32(bytes, rows); append_u32(bytes, columns);
        const auto encoded = encode_q_polynomials(*matrix);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return bytes;
}

ProofCrs decode_crs(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 1886764) throw std::invalid_argument("wrong CRS size");
    Reader reader{bytes};
    reader.magic("BLRSCR01");
    if (reader.integer(2) != 1 || reader.integer(8) != proof_modulus || reader.integer(2) != 64)
        throw std::invalid_argument("unknown CRS parameters");
    ProofCrs crs;
    for (const auto [matrix, rows, columns] : {
        std::tuple{&crs.A1, 20U, 23U}, std::tuple{&crs.A2prime, 20U, 75U},
        std::tuple{&crs.Bprime, 23U, 75U}}) {
        if (reader.integer(4) != rows || reader.integer(4) != columns)
            throw std::invalid_argument("wrong CRS matrix dimensions");
        matrix->resize(rows*columns);
        for (auto& poly : *matrix) for (auto& x : poly) {
            x = reader.integer(8);
            if (x >= proof_modulus) throw std::invalid_argument("noncanonical CRS residue");
        }
    }
    return crs;
}

std::string proof_manifest(const CandidateParameters& parameters, CoreProfile profile, SignatureEncoding encoding) {
    if ((profile != CoreProfile::Ordinary && profile != CoreProfile::Bimodal) ||
        (encoding != SignatureEncoding::Raw && encoding != SignatureEncoding::Compressed))
        throw std::invalid_argument("unknown candidate profile");
    const bool bimodal = profile == CoreProfile::Bimodal;
    const auto wire = encoding == SignatureEncoding::Raw
        ? std::string("{\"body_bytes\":87168,\"challenge_bytes\":2,\"format\":\"raw-v1\",\"header_bytes\":466,\"q_bytes\":8,\"signed_bytes\":8}")
        : "{\"body_bytes_max\":" + std::to_string(compressed_body_max_bytes(profile)) +
          ",\"body_bytes_min\":" + std::to_string(compressed_body_min_bytes(profile)) +
          ",\"challenge_bits\":5,\"format\":\"lossless-rice-v2\",\"header_bytes\":466,\"hint_low_bits\":8,"
          "\"omitted_h_lanes\":[0,32],\"q_bits\":60,\"range_low_bits\":19,\"unary_escape\":31,"
          "\"z1_low_bits\":" + std::to_string(compressed_z1_bits(profile)) + ",\"z21_low_bits\":16}";
    const auto statement_id = statement_identifier(parameters.statement, parameters.context);
    const auto crs_id = framed_identifier("BLRS/commitment-key/v1", encode_crs(parameters.crs));
    // Fixed, canonical schema. No installed defaults or external JSON parsing.
    return "{\"D\":0,\"Q\":1151179879138398721,\"Q_factors\":[65437,17592186058933],"
        "\"adapter_revision\":\"blrs-research-dual-core-exact-v2\","
        "\"backend_revision\":\"3330e487228f633eceb322807b13a596b516770f\","
        "\"binary_map_polynomials\":24,\"challenge\":{\"coefficient_bound\":8,\"independent_coefficients\":32,\"middle_zero\":true,\"operator_bound\":504,\"self_adjoint\":true},"
        "\"commitment_encoding\":\"blrs-explicit-crs-v1\",\"commitment_key_digest\":\"" + hex(crs_id) +
        "\",\"compiler_revision\":\"blrs-sparse-evaluations-v1\",\"core_message_polynomials\":13,"
        "\"crt_primes\":[1125899906840833,1125899906839937,1125899906837633],\"degree\":64,\"ell\":18,"
        "\"encoding\":" + wire + ","
        "\"evaluation\":{\"expanded_variables\":80,\"garbage_polynomials\":5,\"lambda\":10,\"lanes\":[0,32],\"lower_variables\":90,\"scalar_equations\":1133},"
        "\"gamma\":512,\"hint_abs_max\":1124199100721092,\"implementation_digest\":\"" + std::string(blrs_implementation_digest) +
        "\",\"internal_hash_suite\":\"SHAKE128\",\"internal_rng_suite\":\"AES256CTR\",\"k_mlwe\":52,\"k_sis\":20,\"l\":17,"
        "\"layout\":{\"base_h\":5,\"c\":1,\"hint\":20,\"tA1\":20,\"tB\":23,\"z1\":23,\"z21\":75,\"z3\":4,\"z4\":0},"
        "\"lext\":6,\"m1\":23,\"m2\":95,\"nu\":1,\"outer_hash_suite\":\"SHAKE256\",\"quad_many\":{\"l\":22,\"lext\":1},\"radices\":[8,8,8,8,16],"
        "\"range\":{\"extracted_abs_max\":19503514,\"infinity_cap\":9751757,\"projection_columns\":1536,\"projection_law\":\"bit-difference\",\"projection_rows\":256},"
        "\"ring_length\":65536,\"sampler\":{\"algorithm\":\"CKS-rational-with-interval-coins-v1\",\"exponent_max\":30,\"exponent_min\":0,\"finite_abort_error_certified\":false,"
        "\"modes\":[\"" + std::string(bimodal ? "bimodal" : "ordinary") +
        "\",\"one-sided-bimodal\",\"ordinary\"],\"multipliers\":[" + std::string(bimodal ? "2" : "4") +
        ",2,4],\"proposal_limit\":1048576,\"sigma1\":{\"denominator\":5,\"numerator\":" +
        std::string(bimodal ? "126976" : "2031616") + "},\"sigma2\":{\"denominator\":5,\"numerator\":253952},"
        "\"sigma3\":{\"denominator\":5,\"numerator\":2031616},\"variable_time\":true,\"work_limit\":4096},"
        "\"secret_width\":18,\"spec_version\":\"0.4-research-candidate\",\"statement_id\":\"" + hex(statement_id) +
        "\",\"z1_abs_max\":" + std::to_string(z1_coefficient_bound(profile)) +
        ",\"z1_norm_squared_max\":" + std::string(bimodal ? "1898633242869" : "486050110174658") +
        ",\"z21_abs_max\":5618953,\"z2_norm_squared_max\":31572639091752}";
}

Candidate::Candidate(CandidateParameters parameters, CoreProfile profile, SignatureEncoding encoding)
    : parameters_(std::move(parameters)),
      statement_id_(statement_identifier(parameters_.statement, parameters_.context)),
      profile_(profile), encoding_(encoding), backend_(parameters_.crs, profile) {
    const auto manifest = proof_manifest(parameters_, profile_, encoding_);
    proof_id_ = framed_identifier("BLRS/proof/v1", std::span(
        reinterpret_cast<const std::uint8_t*>(manifest.data()), manifest.size()));
}

std::optional<ResearchSignature> Candidate::sign_research(std::span<const Key> ring,
    std::span<const std::uint8_t> message, const Secret& secret, std::size_t index,
    RandomSource& random, SigningMetrics& metrics, std::size_t attempt_limit) const {
    if (ring.size() != ring_size || index >= ring.size()) throw std::invalid_argument("wrong ring/index");
    if (public_key(parameters_.statement, secret) != ring[index]) throw std::invalid_argument("wrong signing key");
    ResearchSignature sig;
    sig.statement_id = statement_id_; sig.proof_id = proof_id_;
    sig.ring_id = ring_identifier(statement_id_, ring);
    sig.tag = link_tag(parameters_.statement, secret);
    metrics = {};
    for (; metrics.attempts < attempt_limit;) {
        ++metrics.attempts;
        Clock::time_point interrupted_start;
        double* interrupted_phase = nullptr;
        try {
            ExactSampler sampler(random);
            std::array<std::uint8_t, 1> sign_byte{};
            random.fill(sign_byte);
            const int sign = (sign_byte[0] & 1) ? 1 : -1;
            std::array<std::array<std::uint16_t,144>,4> blocks{};
            auto witness = make_witness(secret, index, sign, blocks);
            Opening opening;
            for (std::size_t i = 0; i < 23; ++i) opening.small[i] = q_polynomial(witness.small[i]);
            opening.message[0] = q_polynomial(witness.message[0]);
            fill_rho(opening, random);
            backend_.commit(opening);
            sig.base.tA1 = opening.tA1; sig.base.tB = opening.tB;
            auto prefix = initial_prefix(sig, message);
            std::array<Projection,4> projections;
            CoefficientMatrix table;
            const auto fold_start = Clock::now();
            for (unsigned stage = 0; stage < 4; ++stage) {
                projections[stage] = derive_projection(prefix, stage);
                table = stage == 0 ? fold_ring(ring, projections[stage]) : fold_matrix(table, projections[stage]);
                blocks[stage] = witness_column(table, index, stage+1);
                for (std::size_t j = 0; j < 144; ++j)
                    witness.message[1+stage*3+j/64][j%64] = sign*std::int64_t(blocks[stage][j]);
                for (std::size_t j = 0; j < 3; ++j)
                    opening.message[1+stage*3+j] = q_polynomial(witness.message[1+stage*3+j]);
                backend_.commit(opening);
                append_h(prefix, stage, opening.tB);
            }
            metrics.fold_seconds += elapsed(fold_start);
            const auto range_start = Clock::now();
            interrupted_start = range_start;
            interrupted_phase = &metrics.range_seconds;
            std::array<std::int64_t,256> masks{};
            sampler.gaussian(masks, 18);
            for (std::size_t j = 0; j < masks.size(); ++j) witness.message[13+j/64][j%64] = masks[j];
            for (std::size_t j = 13; j < 17; ++j) opening.message[j] = q_polynomial(witness.message[j]);
            backend_.commit(opening);
            append_frame(prefix, "BLRS/range-mask/v1", encode_q_polynomials(std::span(opening.tB).subspan(13,4)));
            auto range = derive_range_matrix(prefix);
            const auto shift = project_binary(range, binary_map(witness));
            for (std::size_t j = 0; j < masks.size(); ++j) sig.range_response[j] = masks[j]+shift[j];
            bool accepted = sampler.ordinary_accept(sig.range_response, shift, 18, 4);
            for (const auto x : sig.range_response) accepted &= x >= -range_cap && x <= range_cap;
            metrics.range_seconds += elapsed(range_start);
            interrupted_phase = nullptr;
            if (!accepted) { ++metrics.range_rejections; continue; }
            append_frame(prefix, "BLRS/range-response/v1", encode_signed_coefficients(sig.range_response));
            const auto compile_start = Clock::now();
            auto equations = compile_evaluations(parameters_.statement, sig.tag, projections, table, range, sig.range_response);
            const auto seed = base_seed(prefix, equations);
            metrics.compile_seconds += elapsed(compile_start);
            Seed masks_seed{};
            random.fill(masks_seed);
            const auto base_start = Clock::now();
            interrupted_start = base_start;
            interrupted_phase = &metrics.base_seconds;
            auto proof = backend_.prove_one_attempt(opening, equations, seed, masks_seed, sampler);
            metrics.base_seconds += elapsed(base_start);
            interrupted_phase = nullptr;
            if (!proof) { ++metrics.base_rejections; continue; }
            sig.base = *proof;
            validate_signature(sig, profile_);
            return sig;
        } catch (const SamplingFailure&) {
            if (interrupted_phase) *interrupted_phase += elapsed(interrupted_start);
            ++metrics.sampler_aborts;
        }
    }
    return std::nullopt;
}

bool Candidate::verify_research(std::span<const Key> ring, std::span<const std::uint8_t> message,
                               const ResearchSignature& sig) const {
    try {
        if (ring.size() != ring_size || sig.statement_id != statement_id_ || sig.proof_id != proof_id_)
            return false;
        validate_signature(sig, profile_);
        if (sig.ring_id != ring_identifier(statement_id_, ring)) return false;
        auto prefix = initial_prefix(sig, message);
        std::array<Projection,4> projections;
        CoefficientMatrix table;
        for (unsigned stage = 0; stage < 4; ++stage) {
            projections[stage] = derive_projection(prefix, stage);
            table = stage == 0 ? fold_ring(ring, projections[stage]) : fold_matrix(table, projections[stage]);
            append_h(prefix, stage, sig.base.tB);
        }
        append_frame(prefix, "BLRS/range-mask/v1", encode_q_polynomials(std::span(sig.base.tB).subspan(13,4)));
        auto range = derive_range_matrix(prefix);
        append_frame(prefix, "BLRS/range-response/v1", encode_signed_coefficients(sig.range_response));
        auto equations = compile_evaluations(parameters_.statement, sig.tag, projections, table, range, sig.range_response);
        return backend_.verify(sig.base, equations, base_seed(prefix, equations));
    } catch (const std::exception&) { return false; }
}

bool Candidate::link_research(std::span<const Key> first_ring, std::span<const std::uint8_t> first_message,
    const ResearchSignature& first, std::span<const Key> second_ring,
    std::span<const std::uint8_t> second_message, const ResearchSignature& second) const {
    return first.tag == second.tag && first.statement_id == second.statement_id &&
        verify_research(first_ring, first_message, first) && verify_research(second_ring, second_message, second);
}

bool Candidate::verify_research(std::span<const Key> ring, std::span<const std::uint8_t> message,
                               std::span<const std::uint8_t> encoded) const {
    try { return verify_research(ring, message, decode_signature(encoded, profile_, encoding_)); }
    catch (const std::exception&) { return false; }
}

Bytes encode_signature(const ResearchSignature& sig, CoreProfile profile, SignatureEncoding encoding) {
    validate_signature(sig, profile);
    if (encoding != SignatureEncoding::Raw && encoding != SignatureEncoding::Compressed)
        throw std::invalid_argument("unknown signature encoding");
    const bool compressed = encoding == SignatureEncoding::Compressed;
    const auto body = compressed ? encode_compressed_body(sig.base, sig.range_response, profile) : Bytes{};
    Bytes bytes{'B','L','R','S','B','0','0',static_cast<std::uint8_t>(compressed ? '2' : '1')};
    bytes.reserve(compressed ? 466+body.size() : raw_signature_bytes);
    append_u16(bytes, compressed ? 2 : 1);
    for (const auto* id : {&sig.statement_id, &sig.proof_id, &sig.ring_id}) bytes.insert(bytes.end(), id->begin(), id->end());
    const auto tag = encode_key(sig.tag); bytes.insert(bytes.end(), tag.begin(), tag.end());
    append_u64(bytes, compressed ? body.size() : raw_signature_bytes-466);
    if (compressed) {
        bytes.insert(bytes.end(), body.begin(), body.end());
        return bytes;
    }
    for (const auto& poly : sig.base.tB) for (auto x : poly) append_u64(bytes,x);
    for (const auto& poly : sig.base.base_h) for (auto x : poly) append_u64(bytes,x);
    for (const auto& poly : sig.base.tA1) for (auto x : poly) append_u64(bytes,x);
    for (auto x : sig.base.c) append_u16(bytes, static_cast<std::uint16_t>(x));
    for (const auto& poly : sig.base.hint) for (auto x : poly) append_u64(bytes, std::bit_cast<std::uint64_t>(x));
    for (const auto& poly : sig.base.z1) for (auto x : poly) append_u64(bytes, std::bit_cast<std::uint64_t>(x));
    for (const auto& poly : sig.base.z21) for (auto x : poly) append_u64(bytes, std::bit_cast<std::uint64_t>(x));
    for (auto x : sig.range_response) append_u64(bytes, std::bit_cast<std::uint64_t>(x));
    if (bytes.size() != raw_signature_bytes) throw std::logic_error("signature size mismatch");
    return bytes;
}

ResearchSignature decode_signature(std::span<const std::uint8_t> bytes, CoreProfile profile, SignatureEncoding encoding) {
    if (encoding != SignatureEncoding::Raw && encoding != SignatureEncoding::Compressed)
        throw std::invalid_argument("unknown signature encoding");
    const bool compressed = encoding == SignatureEncoding::Compressed;
    if (compressed ? (bytes.size() < 466+compressed_body_min_bytes(profile) ||
                      bytes.size() > 466+compressed_body_max_bytes(profile)) : bytes.size() != raw_signature_bytes)
        throw std::invalid_argument("wrong signature size");
    Reader reader{bytes}; reader.magic(compressed ? "BLRSB002" : "BLRSB001");
    if (reader.integer(2) != (compressed ? 2U : 1U)) throw std::invalid_argument("unknown signature version");
    ResearchSignature sig;
    for (auto* id : {&sig.statement_id, &sig.proof_id, &sig.ring_id}) {
        const auto value = reader.take(64); std::copy(value.begin(), value.end(), id->begin());
    }
    for (auto& poly : sig.tag) for (auto& x : poly) {
        const auto raw = reader.integer(2);
        if (raw >= field_prime) throw std::invalid_argument("noncanonical tag");
        x = static_cast<std::uint16_t>(raw);
    }
    if (reader.integer(8) != bytes.size()-466) throw std::invalid_argument("wrong body length");
    if (compressed) {
        auto body = decode_compressed_body(reader.take(bytes.size()-466), profile);
        sig.base = body.base;
        sig.range_response = body.range_response;
        validate_signature(sig, profile);
        return sig;
    }
    for (auto& poly : sig.base.tB) for (auto& x : poly) x = reader.integer(8);
    for (auto& poly : sig.base.base_h) for (auto& x : poly) x = reader.integer(8);
    for (auto& poly : sig.base.tA1) for (auto& x : poly) x = reader.integer(8);
    for (auto& x : sig.base.c) x = std::bit_cast<std::int16_t>(static_cast<std::uint16_t>(reader.integer(2)));
    for (auto& poly : sig.base.hint) for (auto& x : poly) x = std::bit_cast<std::int64_t>(reader.integer(8));
    for (auto& poly : sig.base.z1) for (auto& x : poly) x = std::bit_cast<std::int64_t>(reader.integer(8));
    for (auto& poly : sig.base.z21) for (auto& x : poly) x = std::bit_cast<std::int64_t>(reader.integer(8));
    for (auto& x : sig.range_response) x = std::bit_cast<std::int64_t>(reader.integer(8));
    validate_signature(sig, profile);
    return sig;
}

} // namespace blrs
