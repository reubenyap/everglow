#include "blrs/candidate.hpp"
#include <cassert>
#include <iostream>
#include <limits>

int main() {
    using namespace blrs;
    const auto encode = [](const ResearchSignature& sig) {
        return encode_signature(sig,CoreProfile::Ordinary,SignatureEncoding::Raw);
    };
    const auto decode = [](std::span<const std::uint8_t> bytes) {
        return decode_signature(bytes,CoreProfile::Ordinary,SignatureEncoding::Raw);
    };
    const auto rejected = [](auto operation) {
        try { operation(); } catch (const std::invalid_argument&) { return true; }
        return false;
    };
    ProofCrs crs;
    crs.A1.resize(20*23); crs.A2prime.resize(20*75); crs.Bprime.resize(23*75);
    crs.Bprime.back().back() = proof_modulus-1;
    const auto encoded = encode_crs(crs);
    assert(encoded.size() == 1886764);
    assert(encode_crs(decode_crs(encoded)) == encoded);
    assert(rejected([&]{ decode_crs(std::span(encoded).first(encoded.size()-1)); }));
    auto bad = encoded; bad[0] ^= 1;
    assert(rejected([&]{ decode_crs(bad); }));
    bad = encoded; bad[20] = 21;
    assert(rejected([&]{ decode_crs(bad); }));
    crs.Bprime.back().back() = proof_modulus;
    assert(rejected([&]{ encode_crs(crs); }));
    ResearchSignature signature;
    signature.base.c[0] = -8; signature.base.c[1] = 8; signature.base.c[63] = -8;
    auto bytes = encode(signature);
    assert(bytes.size() == raw_signature_bytes);
    assert(encode(decode(bytes)) == bytes);
    for (auto length : {std::size_t(0),std::size_t(465),raw_signature_bytes-1})
        assert(rejected([&]{ decode(std::span(bytes).first(length)); }));
    auto changed = signature; changed.base.base_h[0][32] = 1;
    assert(rejected([&]{ encode(changed); }));
    changed = signature; changed.base.z1[0][0] = std::numeric_limits<std::int64_t>::min();
    assert(rejected([&]{ encode(changed); }));
    changed = signature; changed.base.z21[0][0] = 5618954;
    assert(rejected([&]{ encode(changed); }));
    changed = signature; changed.range_response[0] = 9751758;
    assert(rejected([&]{ encode(changed); }));
    for (const auto profile : {CoreProfile::Ordinary,CoreProfile::Bimodal}) {
        const auto compact = encode_signature(signature,profile,SignatureEncoding::Compressed);
        assert(encode_signature(decode_signature(compact,profile,SignatureEncoding::Compressed),
                                profile,SignatureEncoding::Compressed) == compact);
        assert(rejected([&]{ decode_signature(compact,profile,SignatureEncoding::Raw); }));
        assert(rejected([&]{ decode_signature(bytes,profile,SignatureEncoding::Compressed); }));
        auto bad_length = compact; bad_length[458] ^= 1;
        assert(rejected([&]{ decode_signature(bad_length,profile,SignatureEncoding::Compressed); }));
        auto trailing = compact; trailing.push_back(0);
        assert(rejected([&]{ decode_signature(trailing,profile,SignatureEncoding::Compressed); }));
    }
    CandidateParameters parameters;
    parameters.crs.A1.resize(20*23); parameters.crs.A2prime.resize(20*75); parameters.crs.Bprime.resize(23*75);
    const auto ordinary_raw = proof_manifest(parameters,CoreProfile::Ordinary,SignatureEncoding::Raw);
    const auto bimodal_raw = proof_manifest(parameters,CoreProfile::Bimodal,SignatureEncoding::Raw);
    const auto ordinary_compact = proof_manifest(parameters,CoreProfile::Ordinary,SignatureEncoding::Compressed);
    const auto bimodal_compact = proof_manifest(parameters,CoreProfile::Bimodal,SignatureEncoding::Compressed);
    assert(ordinary_raw != bimodal_raw && ordinary_compact != bimodal_compact &&
           ordinary_raw != ordinary_compact && bimodal_raw != bimodal_compact);
    bytes[458] ^= 1;
    assert(rejected([&]{ decode(bytes); }));
    std::cout << "candidate bounded CRS/signature codec checks passed\n";
}
