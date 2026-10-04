#pragma once

#include "blrs/codec.hpp"
#include "blrs/sampler.hpp"
#include <string>

namespace blrs {

inline constexpr std::size_t raw_signature_bytes = 87634;

struct CandidateParameters {
    StatementSetup statement;
    ProofCrs crs;
    Bytes context;
};

struct ResearchSignature {
    Identifier statement_id{}, proof_id{}, ring_id{};
    Key tag{};
    BaseProof base;
    std::array<std::int64_t, 256> range_response{};
};

struct SigningMetrics {
    std::size_t attempts = 0, range_rejections = 0, base_rejections = 0, sampler_aborts = 0;
    double fold_seconds = 0, range_seconds = 0, compile_seconds = 0, base_seconds = 0;
};

CandidateParameters generate_parameters(RandomSource& random, Bytes context = {});
Bytes encode_crs(const ProofCrs& crs);
ProofCrs decode_crs(std::span<const std::uint8_t> bytes);
std::string proof_manifest(const CandidateParameters& parameters,
    CoreProfile profile = CoreProfile::Bimodal,
    SignatureEncoding encoding = SignatureEncoding::Compressed);

// Research API only: passing tests does not certify quantum signature security.
class Candidate {
public:
    explicit Candidate(CandidateParameters parameters,
        CoreProfile profile = CoreProfile::Bimodal,
        SignatureEncoding encoding = SignatureEncoding::Compressed);
    const CandidateParameters& parameters() const { return parameters_; }
    const Identifier& statement_id() const { return statement_id_; }
    const Identifier& proof_id() const { return proof_id_; }
    CoreProfile profile() const { return profile_; }
    SignatureEncoding encoding() const { return encoding_; }
    std::optional<ResearchSignature> sign_research(std::span<const Key> ring,
        std::span<const std::uint8_t> message, const Secret& secret,
        std::size_t index, RandomSource& random, SigningMetrics& metrics,
        std::size_t attempt_limit = 256) const;
    bool verify_research(std::span<const Key> ring, std::span<const std::uint8_t> message,
                         const ResearchSignature& signature) const;
    bool verify_research(std::span<const Key> ring, std::span<const std::uint8_t> message,
                         std::span<const std::uint8_t> encoded) const;
    bool link_research(std::span<const Key> first_ring, std::span<const std::uint8_t> first_message,
        const ResearchSignature& first, std::span<const Key> second_ring,
        std::span<const std::uint8_t> second_message, const ResearchSignature& second) const;
private:
    CandidateParameters parameters_;
    Identifier statement_id_{}, proof_id_{};
    CoreProfile profile_;
    SignatureEncoding encoding_;
    Backend backend_;
};

Bytes encode_signature(const ResearchSignature& signature,
    CoreProfile profile = CoreProfile::Bimodal,
    SignatureEncoding encoding = SignatureEncoding::Compressed);
ResearchSignature decode_signature(std::span<const std::uint8_t> bytes,
    CoreProfile profile = CoreProfile::Bimodal,
    SignatureEncoding encoding = SignatureEncoding::Compressed);

} // namespace blrs
