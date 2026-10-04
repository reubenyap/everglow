#pragma once

#include "backend.hpp"

namespace blrs {

enum class SignatureEncoding : std::uint8_t { Raw, Compressed };

struct CompressedBody {
    BaseProof base;
    std::array<std::int64_t, 256> range_response{};
};

// Lossless wire compression only. Commitment rounding remains D = 0.
inline constexpr unsigned compressed_q_bits = 60;
inline constexpr unsigned compressed_hint_bits = 8;
inline constexpr unsigned compressed_z21_bits = 16;
inline constexpr unsigned compressed_range_bits = 19;
inline constexpr unsigned compressed_unary_escape = 31;

unsigned compressed_z1_bits(CoreProfile profile);
std::size_t compressed_body_min_bytes(CoreProfile profile);
std::size_t compressed_body_max_bytes(CoreProfile profile);
void validate_proof_body(const BaseProof& base,
    const std::array<std::int64_t, 256>& range_response, CoreProfile profile);
Bytes encode_compressed_body(const BaseProof& base,
    const std::array<std::int64_t, 256>& range_response, CoreProfile profile);
CompressedBody decode_compressed_body(std::span<const std::uint8_t> bytes,
    CoreProfile profile);

} // namespace blrs
