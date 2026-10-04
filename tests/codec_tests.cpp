#include "blrs/codec.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <string>

namespace {
using namespace blrs;

template<typename Operation>
bool rejected(Operation operation) {
    try { operation(); } catch (const std::invalid_argument&) { return true; }
    return false;
}

void overwrite_bits(Bytes& bytes, std::size_t position, std::uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) {
        const auto mask = static_cast<std::uint8_t>(1U << ((position+i) & 7U));
        auto& byte = bytes[(position+i)/8];
        byte = static_cast<std::uint8_t>((byte & static_cast<std::uint8_t>(~mask))
            | ((((value >> i) & 1U) != 0) ? mask : 0));
    }
}

std::string digest(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto value : shake256(bytes, 64)) {
        result += digits[value >> 4]; result += digits[value & 15];
    }
    return result;
}

CompressedBody fixture() {
    CompressedBody body;
    body.base.tB[0][0] = proof_modulus-1;
    body.base.base_h[4][63] = proof_modulus-2;
    body.base.tA1[19][63] = proof_modulus-3;
    for (std::size_t i = 0; i < 32; ++i) body.base.c[i] = static_cast<std::int64_t>(i%17)-8;
    for (std::size_t i = 1; i < 32; ++i) body.base.c[64-i] = -body.base.c[i];
    body.base.hint[0][0] = -1; body.base.hint[0][1] = 1;
    body.base.hint[0][3] = 1124199100721092;
    body.base.hint[0][4] = -1124199100721092;
    body.base.z1[0][0] = 18000; body.base.z1[0][1] = -123456;
    body.base.z21[0][0] = 45678; body.base.z21[74][63] = -56789;
    body.range_response[0] = range_response_cap;
    body.range_response[1] = -range_response_cap;
    return body;
}

void roundtrip(const CompressedBody& body, CoreProfile profile) {
    const auto encoded = encode_compressed_body(body.base, body.range_response, profile);
    const auto decoded = decode_compressed_body(encoded, profile);
    assert(decoded.base.tB == body.base.tB && decoded.base.base_h == body.base.base_h);
    assert(decoded.base.tA1 == body.base.tA1 && decoded.base.c == body.base.c);
    assert(decoded.base.hint == body.base.hint && decoded.base.z1 == body.base.z1);
    assert(decoded.base.z21 == body.base.z21 && decoded.range_response == body.range_response);
    assert(encode_compressed_body(decoded.base, decoded.range_response, profile) == encoded);
}
} // namespace

int main() {
    using namespace blrs;
    constexpr std::size_t challenge_offset = (48*64-10)*60;
    constexpr std::size_t hint_offset = challenge_offset + 32*5;
    for (const auto profile : {CoreProfile::Ordinary, CoreProfile::Bimodal}) {
        CompressedBody zero;
        const auto minimal = encode_compressed_body(zero.base, zero.range_response, profile);
        assert(minimal.size() == compressed_body_min_bytes(profile));
        assert(compressed_body_min_bytes(profile) == (profile == CoreProfile::Ordinary ? 38946 : 38210));
        assert(compressed_body_max_bytes(profile) == (profile == CoreProfile::Ordinary ? 81386 : 80650));
        roundtrip(zero, profile);
        const auto known = fixture();
        const auto encoded = encode_compressed_body(known.base, known.range_response, profile);
        // Independently generated with Python integer floor division and hashlib.shake_256.
        if (profile == CoreProfile::Ordinary) {
            assert(encoded.size() == 38973);
            assert(digest(encoded) == "190ada60b459d387444ec1af1840f1e4421079248f6330b128dc7eb11ae85ca2d7"
                "81abfd57f086cda2ae0420ec70ca315e38fadfc802ab09cafd612633a7515b");
        } else {
            assert(encoded.size() == 38238);
            assert(digest(encoded) == "f28706fb35db08ba87ac65f57317e34d5d959f702f814b24290e82c177f1bb265d3"
                "0ab2dab52fd41e99e36868305ffff118c9eb0c51d52482326021a53486298");
        }
        roundtrip(known, profile);
        const auto width = compressed_z1_bits(profile);
        const auto half = std::int64_t(1) << (width-1);
        const auto scale = 2*half;
        for (const auto value : {half-1, half, half+1, -half-1, -half, -half+1,
                                16*scale-1, 16*scale, -16*scale, -16*scale+1}) {
            auto boundary = zero;
            boundary.base.z1[0][0] = value;
            roundtrip(boundary, profile);
        }
        for (const auto value : {std::int64_t(22046544), std::int64_t(1377909)}) {
            if (profile == CoreProfile::Bimodal && value > 1377909) continue;
            auto boundary = zero; boundary.base.z1[0][0] = value;
            roundtrip(boundary, profile);
            boundary.base.z1[0][0] = -value; roundtrip(boundary, profile);
        }
        for (const auto value : {std::int64_t(32767), std::int64_t(32768), std::int64_t(-32768),
                                std::int64_t(-32769), std::int64_t(5618953), std::int64_t(-5618953)}) {
            auto boundary = zero; boundary.base.z21[0][0] = value;
            roundtrip(boundary, profile);
        }
        for (const auto length : {std::size_t(0), minimal.size()-1, encoded.size()-1})
            assert(rejected([&]{ decode_compressed_body(std::span(encoded).first(length), profile); }));
        auto bad = minimal; bad.push_back(0);
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        bad = minimal; bad.back() |= 0x80;
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        bad = minimal; bad.back() = 0;
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        bad = minimal; overwrite_bits(bad, 0, proof_modulus, 60);
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        bad = minimal; overwrite_bits(bad, challenge_offset, 17, 5);
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        bad = minimal;
        overwrite_bits(bad, hint_offset, (std::uint64_t(1)<<31)-1, 31);
        overwrite_bits(bad, hint_offset+31, 0, 51);
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        overwrite_bits(bad, hint_offset+31, std::uint64_t(1)<<50, 51);
        assert(rejected([&]{ decode_compressed_body(bad, profile); }));
        Bytes excessive(compressed_body_max_bytes(profile)+1, 0xff);
        assert(rejected([&]{ decode_compressed_body(excessive, profile); }));
        auto invalid = zero; invalid.base.base_h[0][32] = 1;
        assert(rejected([&]{ encode_compressed_body(invalid.base, invalid.range_response, profile); }));
        invalid = zero; invalid.base.z1[0][0] = std::numeric_limits<std::int64_t>::min();
        assert(rejected([&]{ encode_compressed_body(invalid.base, invalid.range_response, profile); }));
        invalid = zero;
        std::fill(invalid.base.z1[0].begin(), invalid.base.z1[0].end(),
                  profile == CoreProfile::Ordinary ? 22046544 : 1377909);
        assert(rejected([&]{ encode_compressed_body(invalid.base, invalid.range_response, profile); }));
        invalid = zero; invalid.base.z21[0][0] = 5618954;
        assert(rejected([&]{ encode_compressed_body(invalid.base, invalid.range_response, profile); }));
        invalid = zero; invalid.range_response[0] = range_response_cap+1;
        assert(rejected([&]{ encode_compressed_body(invalid.base, invalid.range_response, profile); }));
    }
    auto wrong_profile = static_cast<CoreProfile>(99);
    assert(rejected([&]{ compressed_body_min_bytes(wrong_profile); }));
    std::cout << "compressed codec checks and independent Python oracle digests passed\n";
}
