#include "blrs/codec.hpp"

#include <bit>
#include <stdexcept>

namespace blrs {
namespace {
constexpr std::int64_t hint_cap = 1124199100721092;
constexpr std::int64_t z21_cap = 5618953;
constexpr std::uint64_t z2_norm_cap = 31572639091752;
constexpr std::size_t residue_bits = (48 * 64 - 10) * compressed_q_bits;
constexpr std::size_t challenge_bits = 32 * 5;

void check_profile(CoreProfile profile) {
    if (profile != CoreProfile::Ordinary && profile != CoreProfile::Bimodal)
        throw std::invalid_argument("unknown compressed core profile");
}

unsigned signed_width(std::int64_t cap) {
    return static_cast<unsigned>(std::bit_width(static_cast<std::uint64_t>(cap))) + 1;
}

std::int64_t z1_cap(CoreProfile profile) {
    check_profile(profile);
    return profile == CoreProfile::Ordinary ? 22046544 : 1377909;
}

std::uint64_t z1_norm_cap(CoreProfile profile) {
    return profile == CoreProfile::Ordinary ? 486050110174658ULL : 1898633242869ULL;
}

struct Writer {
    Bytes bytes;
    unsigned offset = 0;
    void bit(bool value) {
        if (offset == 0) bytes.push_back(0);
        if (value) bytes.back() |= static_cast<std::uint8_t>(1U << offset);
        offset = (offset + 1) & 7U;
    }
    void integer(std::uint64_t value, unsigned width) {
        for (unsigned i = 0; i < width; ++i) bit(((value >> i) & 1U) != 0);
    }
    void finish() { bit(true); }
};

struct Reader {
    std::span<const std::uint8_t> bytes;
    std::size_t position = 0;
    bool bit() {
        if (position / 8 >= bytes.size()) throw std::invalid_argument("truncated compressed body");
        const bool value = ((bytes[position / 8] >> (position & 7U)) & 1U) != 0;
        ++position;
        return value;
    }
    std::uint64_t integer(unsigned width) {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i) value |= std::uint64_t(bit()) << i;
        return value;
    }
    void finish() {
        if (!bit()) throw std::invalid_argument("missing compressed terminator");
        if ((position + 7) / 8 != bytes.size())
            throw std::invalid_argument("trailing compressed bytes");
        while ((position & 7U) != 0)
            if (bit()) throw std::invalid_argument("nonzero compressed padding");
    }
};

std::int64_t signed_integer(Reader& reader, unsigned width) {
    const auto value = reader.integer(width);
    if ((value & (std::uint64_t(1) << (width - 1))) != 0)
        return static_cast<std::int64_t>(value) - (std::int64_t(1) << width);
    return static_cast<std::int64_t>(value);
}

std::int64_t quotient(std::int64_t value, unsigned width) {
    const auto scale = std::int64_t(1) << width;
    // Floor((value + scale/2)/scale), with a centered low part in [-scale/2,scale/2).
    const auto shifted = value + scale / 2;
    auto result = shifted / scale;
    if (shifted < 0 && shifted % scale != 0) --result;
    return result;
}

std::uint64_t unary_length(std::int64_t high) {
    return static_cast<std::uint64_t>(high <= 0 ? -2 * high : 2 * high - 1);
}

void bounded(std::int64_t value, std::int64_t cap) {
    if (value < -cap || value > cap) throw std::invalid_argument("compressed coefficient bound");
}

void encode_signed(Writer& writer, std::int64_t value, unsigned width, std::int64_t cap) {
    bounded(value, cap);
    const auto high = quotient(value, width);
    const auto count = unary_length(high);
    if (count >= compressed_unary_escape) {
        for (unsigned i = 0; i < compressed_unary_escape; ++i) writer.bit(true);
        writer.integer(static_cast<std::uint64_t>(value), signed_width(cap));
    } else {
        for (unsigned i = 0; i < count; ++i) writer.bit(true);
        writer.bit(false);
        const auto low = value - high * (std::int64_t(1) << width);
        writer.integer(static_cast<std::uint64_t>(low), width);
    }
}

std::int64_t decode_signed(Reader& reader, unsigned width, std::int64_t cap) {
    unsigned count = 0;
    while (count < compressed_unary_escape && reader.bit()) ++count;
    std::int64_t value;
    if (count == compressed_unary_escape) {
        value = signed_integer(reader, signed_width(cap));
        bounded(value, cap);
        if (unary_length(quotient(value, width)) < compressed_unary_escape)
            throw std::invalid_argument("noncanonical compressed escape");
    } else {
        const auto high = (count & 1U) != 0 ? std::int64_t(count + 1) / 2 : -std::int64_t(count) / 2;
        value = high * (std::int64_t(1) << width) + signed_integer(reader, width);
        bounded(value, cap);
    }
    return value;
}

template<typename Polys>
void check_norm(const Polys& polys, std::uint64_t cap) {
    unsigned __int128 norm = 0;
    for (const auto& poly : polys) for (const auto value : poly) {
        const auto x = static_cast<__int128>(value);
        norm += static_cast<unsigned __int128>(x * x);
    }
    if (norm > cap) throw std::invalid_argument("compressed response norm bound");
}

void check_challenge(const SignedPoly& challenge) {
    for (const auto value : challenge) bounded(value, 8);
    if (challenge[32] != 0) throw std::invalid_argument("compressed challenge middle lane");
    for (std::size_t i = 1; i < 32; ++i)
        if (challenge[64-i] != -challenge[i])
            throw std::invalid_argument("compressed challenge symmetry");
}

void write_residue(Writer& writer, std::uint64_t value) {
    if (value >= proof_modulus) throw std::invalid_argument("noncanonical compressed residue");
    writer.integer(value, compressed_q_bits);
}

std::uint64_t read_residue(Reader& reader) {
    const auto value = reader.integer(compressed_q_bits);
    if (value >= proof_modulus) throw std::invalid_argument("noncanonical compressed residue");
    return value;
}
} // namespace

unsigned compressed_z1_bits(CoreProfile profile) {
    check_profile(profile);
    return profile == CoreProfile::Ordinary ? 19 : 15;
}

std::size_t compressed_body_min_bytes(CoreProfile profile) {
    const std::size_t bits = residue_bits + challenge_bits + 1280 * (1 + compressed_hint_bits)
        + 1472 * (1 + compressed_z1_bits(profile)) + 4800 * (1 + compressed_z21_bits)
        + 256 * (1 + compressed_range_bits) + 1;
    return (bits + 7) / 8;
}

std::size_t compressed_body_max_bytes(CoreProfile profile) {
    const std::size_t bits = residue_bits + challenge_bits
        + 1280 * (compressed_unary_escape + signed_width(hint_cap))
        + 1472 * (compressed_unary_escape + signed_width(z1_cap(profile)))
        + 4800 * (compressed_unary_escape + signed_width(z21_cap))
        + 256 * (compressed_unary_escape + signed_width(range_response_cap)) + 1;
    return (bits + 7) / 8;
}

void validate_proof_body(const BaseProof& base,
    const std::array<std::int64_t, 256>& range_response, CoreProfile profile) {
    check_profile(profile);
    for (const auto& poly : base.tB) for (const auto x : poly)
        if (x >= proof_modulus) throw std::invalid_argument("noncanonical tB");
    for (const auto& poly : base.base_h) {
        if (poly[0] != 0 || poly[32] != 0) throw std::invalid_argument("nonzero evaluation lanes");
        for (const auto x : poly)
            if (x >= proof_modulus) throw std::invalid_argument("noncanonical h");
    }
    for (const auto& poly : base.tA1) for (const auto x : poly)
        if (x >= proof_modulus) throw std::invalid_argument("noncanonical tA1");
    check_challenge(base.c);
    for (const auto& poly : base.hint) for (const auto x : poly) bounded(x, hint_cap);
    for (const auto& poly : base.z1) for (const auto x : poly) bounded(x, z1_cap(profile));
    for (const auto& poly : base.z21) for (const auto x : poly) bounded(x, z21_cap);
    for (const auto x : range_response) bounded(x, range_response_cap);
    check_norm(base.z1, z1_norm_cap(profile));
    check_norm(base.z21, z2_norm_cap);
}

Bytes encode_compressed_body(const BaseProof& base,
    const std::array<std::int64_t, 256>& range_response, CoreProfile profile) {
    const auto z1_width = compressed_z1_bits(profile);
    validate_proof_body(base, range_response, profile);
    Writer writer;
    writer.bytes.reserve(compressed_body_min_bytes(profile));
    for (const auto& poly : base.tB) for (const auto x : poly) write_residue(writer, x);
    for (const auto& poly : base.base_h)
        for (std::size_t i = 0; i < 64; ++i)
            if (i != 0 && i != 32) write_residue(writer, poly[i]);
    for (const auto& poly : base.tA1) for (const auto x : poly) write_residue(writer, x);
    for (std::size_t i = 0; i < 32; ++i)
        writer.integer(static_cast<std::uint64_t>(base.c[i] + 8), 5);
    for (const auto& poly : base.hint) for (const auto x : poly)
        encode_signed(writer, x, compressed_hint_bits, hint_cap);
    for (const auto& poly : base.z1) for (const auto x : poly)
        encode_signed(writer, x, z1_width, z1_cap(profile));
    for (const auto& poly : base.z21) for (const auto x : poly)
        encode_signed(writer, x, compressed_z21_bits, z21_cap);
    for (const auto x : range_response)
        encode_signed(writer, x, compressed_range_bits, range_response_cap);
    writer.finish();
    if (writer.bytes.size() > compressed_body_max_bytes(profile))
        throw std::logic_error("compressed body size mismatch");
    return std::move(writer.bytes);
}

CompressedBody decode_compressed_body(std::span<const std::uint8_t> bytes, CoreProfile profile) {
    if (bytes.size() < compressed_body_min_bytes(profile)
        || bytes.size() > compressed_body_max_bytes(profile))
        throw std::invalid_argument("wrong compressed body size");
    Reader reader{bytes};
    CompressedBody body;
    for (auto& poly : body.base.tB) for (auto& x : poly) x = read_residue(reader);
    for (auto& poly : body.base.base_h)
        for (std::size_t i = 0; i < 64; ++i)
            if (i != 0 && i != 32) poly[i] = read_residue(reader);
    for (auto& poly : body.base.tA1) for (auto& x : poly) x = read_residue(reader);
    for (std::size_t i = 0; i < 32; ++i) {
        const auto value = reader.integer(5);
        if (value > 16) throw std::invalid_argument("compressed challenge coefficient bound");
        body.base.c[i] = static_cast<std::int64_t>(value) - 8;
    }
    for (std::size_t i = 1; i < 32; ++i) body.base.c[64-i] = -body.base.c[i];
    for (auto& poly : body.base.hint) for (auto& x : poly)
        x = decode_signed(reader, compressed_hint_bits, hint_cap);
    for (auto& poly : body.base.z1) for (auto& x : poly)
        x = decode_signed(reader, compressed_z1_bits(profile), z1_cap(profile));
    for (auto& poly : body.base.z21) for (auto& x : poly)
        x = decode_signed(reader, compressed_z21_bits, z21_cap);
    for (auto& x : body.range_response)
        x = decode_signed(reader, compressed_range_bits, range_response_cap);
    reader.finish();
    validate_proof_body(body.base, body.range_response, profile);
    return body;
}

} // namespace blrs
