#include "blrs/candidate.hpp"
#include <charconv>
#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <sys/resource.h>

namespace {
using Clock = std::chrono::steady_clock;
double seconds(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now()-start).count();
}
std::size_t positive(const char* text) {
    std::size_t value{};
    const std::string_view input(text);
    const auto result = std::from_chars(input.data(), input.data()+input.size(), value);
    if (result.ec != std::errc{} || result.ptr != input.data()+input.size() || value == 0)
        throw std::invalid_argument("option requires a positive integer");
    return value;
}
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void save(const std::string& path, std::span<const std::uint8_t> bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!out) throw std::runtime_error("cannot write benchmark artifact");
}
blrs::Bytes load(const std::string& path, std::size_t maximum) {
    std::ifstream in(path,std::ios::binary|std::ios::ate);
    const auto length = in.tellg();
    if (length < 0 || static_cast<std::uint64_t>(length) > maximum)
        throw std::runtime_error("missing or oversized fixture file");
    blrs::Bytes bytes(static_cast<std::size_t>(length));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
    if (!in || in.peek() != std::char_traits<char>::eof()) throw std::runtime_error("fixture read failed");
    return bytes;
}
void verify_fixture(const std::string& prefix, blrs::CoreProfile profile, blrs::SignatureEncoding encoding) {
    blrs::CandidateParameters parameters;
    parameters.crs = blrs::decode_crs(load(prefix+".crs.bin",1886764));
    const auto statement = load(prefix+".statement.bin",1024*1024);
    require(statement.size() >= 9232,"short statement fixture");
    const auto integer = [&](std::size_t offset, unsigned count) {
        std::uint64_t value = 0;
        for (unsigned i = 0; i < count; ++i) value |= std::uint64_t(statement.at(offset+i)) << (8U*i);
        return value;
    };
    require(integer(0,4) == 65437 && integer(4,2) == 64 && integer(6,2) == 18,"wrong statement fixture profile");
    std::size_t position = 8;
    for (auto* matrix : {&parameters.statement.key_matrix,&parameters.statement.link_matrix})
        for (auto& row : *matrix) for (auto& poly : row) for (auto& value : poly) {
            const auto raw = integer(position,2); position += 2;
            require(raw < blrs::field_prime,"noncanonical statement fixture coefficient");
            value = static_cast<std::uint16_t>(raw);
        }
    require(integer(9224,8) == statement.size()-9232,"wrong statement fixture context length");
    parameters.context.assign(statement.begin()+9232,statement.end());
    blrs::Candidate candidate(std::move(parameters), profile, encoding);
    const auto raw_ring = load(prefix+".ring.bin",65536*256);
    require(raw_ring.size() == 65536*256,"wrong fixture ring size");
    std::vector<blrs::Key> ring(65536);
    position = 0;
    for (auto& key : ring) for (auto& poly : key) for (auto& value : poly) {
        const auto raw = unsigned(raw_ring[position]) | (unsigned(raw_ring[position+1]) << 8);
        position += 2;
        require(raw < blrs::field_prime,"noncanonical fixture key");
        value = static_cast<std::uint16_t>(raw);
    }
    const auto message = load(prefix+".message.bin",1024*1024);
    const auto signature = load(prefix+".signature.bin",blrs::raw_signature_bytes);
    const auto start = Clock::now();
    require(candidate.verify_research(ring,message,signature),"saved fixture did not verify");
    std::cout << "Saved fixture verified in a fresh backend: " << seconds(start) << " s\n";
}
// Decoys are independently uniform canonical keys. They model a full public
// ring for performance; this does not measure generating 65,536 coin outputs.
std::vector<blrs::Key> synthetic_ring(blrs::RandomSource& random) {
    std::vector<blrs::Key> keys(blrs::ring_size);
    std::array<std::uint8_t,8192> buffer{};
    std::size_t position = buffer.size();
    for (auto& key : keys) for (auto& poly : key) for (auto& coefficient : poly) {
        std::uint16_t candidate;
        do {
            if (position == buffer.size()) { random.fill(buffer); position = 0; }
            candidate = static_cast<std::uint16_t>(unsigned(buffer[position]) | (unsigned(buffer[position+1]) << 8));
            position += 2;
        } while (candidate >= blrs::field_prime);
        coefficient = candidate;
    }
    return keys;
}
void mutations(const blrs::Candidate& candidate, std::span<const blrs::Key> ring,
               blrs::Bytes message, const blrs::ResearchSignature& signature) {
    auto bytes = blrs::encode_signature(signature, candidate.profile(), candidate.encoding());
    require(!candidate.verify_research(ring,message,std::span(bytes).first(bytes.size()-1)), "truncation accepted");
    bytes.push_back(0);
    require(!candidate.verify_research(ring,message,bytes), "trailing byte accepted");
    const auto other_profile = candidate.profile() == blrs::CoreProfile::Bimodal
        ? blrs::CoreProfile::Ordinary : blrs::CoreProfile::Bimodal;
    blrs::Candidate other_core(candidate.parameters(),other_profile,candidate.encoding());
    require(!other_core.verify_research(ring,message,signature), "cross-core proof accepted");
    const auto other_encoding = candidate.encoding() == blrs::SignatureEncoding::Compressed
        ? blrs::SignatureEncoding::Raw : blrs::SignatureEncoding::Compressed;
    blrs::Candidate other_wire(candidate.parameters(),candidate.profile(),other_encoding);
    require(!other_wire.verify_research(ring,message,signature), "cross-format proof accepted");
    auto alternate = blrs::encode_signature(signature,candidate.profile(),other_encoding);
    require(!candidate.verify_research(ring,message,alternate), "unexpected wire format accepted");
    auto changed = signature;
    changed.proof_id[0] ^= 1;
    require(!candidate.verify_research(ring,message,changed), "wrong proof identifier accepted");
    changed = signature; changed.statement_id[0] ^= 1;
    require(!candidate.verify_research(ring,message,changed), "wrong statement identifier accepted");
    changed = signature; changed.tag[0][0] = static_cast<std::uint16_t>((changed.tag[0][0]+1U)%blrs::field_prime);
    require(!candidate.verify_research(ring,message,changed), "changed tag accepted");
    changed = signature; changed.base.tB[1][0] = (changed.base.tB[1][0]+1)%blrs::proof_modulus;
    require(!candidate.verify_research(ring,message,changed), "changed commitment accepted");
    changed = signature; changed.base.base_h[0][32] = 1;
    require(!candidate.verify_research(ring,message,changed), "second evaluation lane accepted");
    changed = signature; changed.range_response[0] = 9751758;
    require(!candidate.verify_research(ring,message,changed), "range bound accepted");
    changed = signature; changed.base.z21[0][0] = 5618954;
    require(!candidate.verify_research(ring,message,changed), "z21 bound accepted");
    message[0] ^= 1;
    require(!candidate.verify_research(ring,message,signature), "changed message accepted");
    message[0] ^= 1;
    std::vector<blrs::Key> reordered(ring.begin(),ring.end());
    std::swap(reordered[0],reordered[1]);
    require(!candidate.verify_research(reordered,message,signature), "changed ring accepted");
}

// Test-only: force the private sign while retaining fresh system entropy for
// every mask, commitment and auxiliary. Normal benchmark runs use SystemRandom.
class ForcedSignRandom final : public blrs::RandomSource {
public:
    explicit ForcedSignRandom(int sign) : sign_(sign) {}
    void fill(std::span<std::uint8_t> bytes) override {
        random_.fill(bytes);
        if (bytes.size() == 1) bytes[0] = static_cast<std::uint8_t>(sign_ > 0 ? 1 : 0);
    }
private:
    int sign_;
    blrs::SystemRandom random_;
};

void sign_and_link_tests(const blrs::Candidate& candidate, std::span<const blrs::Key> source_ring,
                        const blrs::Secret& secret) {
    std::vector<blrs::Key> first_ring(source_ring.begin(),source_ring.end()), second_ring(first_ring);
    std::swap(first_ring[0],first_ring[12345]);
    std::swap(second_ring[65535],second_ring[12345]);
    blrs::Bytes first_message{'p','l','u','s'}, second_message{'m','i','n','u','s'};
    ForcedSignRandom plus(1), minus(-1);
    blrs::SigningMetrics metrics;
    std::cerr << "Integration: sign +1 at index 0, sign -1 at index 65,535, verify and link...\n";
    auto first = candidate.sign_research(first_ring,first_message,secret,0,plus,metrics,512);
    if (!first) throw std::runtime_error("positive-sign integration attempt limit exhausted");
    auto second = candidate.sign_research(second_ring,second_message,secret,65535,minus,metrics,512);
    if (!second) throw std::runtime_error("negative-sign integration attempt limit exhausted");
    require(candidate.link_research(first_ring,first_message,*first,second_ring,second_message,*second),"valid same-secret signatures did not link");
    second->base.base_h[0][32] = 1;
    require(!candidate.link_research(first_ring,first_message,*first,second_ring,second_message,*second),"invalid signature linked");
    require(!candidate.sign_research(first_ring,first_message,secret,0,plus,metrics,0),"exhausted attempt limit succeeded");
    require(metrics.attempts == 0,"zero attempt limit performed an attempt");
    std::cerr << "Both signs, endpoint indices, different rings/messages and verified linking passed.\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        std::size_t runs = 1, limit = 256;
        std::string output, fixture;
        bool check_mutations = false;
        auto profile = blrs::CoreProfile::Bimodal;
        auto encoding = blrs::SignatureEncoding::Compressed;
        for (int i = 1; i < argc; ++i) {
            const std::string_view arg(argv[i]);
            if (arg == "--help") {
                std::cout << "blrs_bench [--core bimodal|ordinary] [--encoding compressed|raw] [--runs N]\n"
                    "           [--attempt-limit N] [--output PATH] [--integration-tests]\n"
                    "blrs_bench --verify-fixture PATH [--core bimodal|ordinary] [--encoding compressed|raw]\n";
                return 0;
            }
            if (arg == "--integration-tests") { check_mutations = true; continue; }
            if (++i == argc) throw std::invalid_argument("missing option value");
            if (arg == "--runs") runs = positive(argv[i]);
            else if (arg == "--attempt-limit") limit = positive(argv[i]);
            else if (arg == "--core") {
                const std::string_view value(argv[i]);
                if (value == "bimodal") profile = blrs::CoreProfile::Bimodal;
                else if (value == "ordinary") profile = blrs::CoreProfile::Ordinary;
                else throw std::invalid_argument("unknown core");
            } else if (arg == "--encoding") {
                const std::string_view value(argv[i]);
                if (value == "compressed") encoding = blrs::SignatureEncoding::Compressed;
                else if (value == "raw") encoding = blrs::SignatureEncoding::Raw;
                else throw std::invalid_argument("unknown encoding");
            } else if (arg == "--output") output = argv[i];
            else if (arg == "--verify-fixture") fixture = argv[i];
            else throw std::invalid_argument("unknown option");
        }
        if (!fixture.empty()) { verify_fixture(fixture,profile,encoding); return 0; }
        blrs::SystemRandom random;
        auto start = Clock::now();
        auto parameters = blrs::generate_parameters(random, {'b','e','n','c','h','m','a','r','k'});
        const double setup_seconds = seconds(start);
        const auto manifest = blrs::proof_manifest(parameters,profile,encoding);
        start = Clock::now();
        blrs::Candidate candidate(std::move(parameters), profile, encoding);
        const double backend_init_seconds = seconds(start);
        start = Clock::now();
        auto ring = synthetic_ring(random);
        const auto secret = blrs::generate_secret(random);
        constexpr std::size_t signer = 12345;
        ring[signer] = blrs::public_key(candidate.parameters().statement,secret);
        const double ring_generation_seconds = seconds(start);
        start = Clock::now();
        const auto id = blrs::ring_identifier(candidate.statement_id(),ring);
        (void)id;
        const double ring_hash_seconds = seconds(start);
        std::set<blrs::Key> distinct(ring.begin(),ring.end());
        const auto distinct_count = distinct.size();
        distinct.clear();
        blrs::Bytes message{'b','e','n','c','h','m','a','r','k'};
        if (!output.empty()) {
            save(output+".crs.bin",blrs::encode_crs(candidate.parameters().crs));
            save(output+".ring.bin",blrs::encode_keys(ring));
            save(output+".message.bin",message);
            blrs::Bytes statement;
            blrs::append_u32(statement,blrs::field_prime);
            blrs::append_u16(statement,64); blrs::append_u16(statement,18);
            for (const auto* matrix : {&candidate.parameters().statement.key_matrix,&candidate.parameters().statement.link_matrix})
                for (const auto& row : *matrix) for (const auto& poly : row) for (auto value : poly)
                    blrs::append_u16(statement,value);
            blrs::append_u64(statement,candidate.parameters().context.size());
            statement.insert(statement.end(),candidate.parameters().context.begin(),candidate.parameters().context.end());
            save(output+".statement.bin",statement);
        }
        std::ofstream file;
        if (!output.empty()) { file.open(output); if (!file) throw std::runtime_error("cannot open output"); }
        std::ostream& out = output.empty() ? std::cout : file;
        out.precision(10);
        out << "{\n  \"profile\":\"" << (profile == blrs::CoreProfile::Bimodal ? "bimodal" : "ordinary")
            << "-exact-research\",\n  \"encoding\":\"" << (encoding == blrs::SignatureEncoding::Compressed ? "compressed" : "raw")
            << "\",\n  \"compiler\":\"" << __VERSION__
            << "\",\n  \"ring_keys\":" << ring.size() << ",\n  \"distinct_keys\":" << distinct_count
            << ",\n  \"ring_kind\":\"synthetic-uniform-decoys-with-valid-signer\",\n  \"ring_bytes\":16777216,\n  \"projected_tables_bytes\":2695680,\n  \"crs_bytes\":1886764,\n  \"setup_seconds\":" << setup_seconds
            << ",\n  \"backend_initialization_seconds\":" << backend_init_seconds
            << ",\n  \"ring_generation_seconds\":" << ring_generation_seconds
            << ",\n  \"ring_hash_seconds\":" << ring_hash_seconds << ",\n  \"runs\":[\n";
        std::size_t successes = 0;
        for (std::size_t run = 0; run < runs; ++run) {
            blrs::SigningMetrics metrics;
            start = Clock::now();
            std::cerr << "Signing run " << run+1 << " (65,536 keys, fresh complete attempts)...\n";
            auto signature = candidate.sign_research(ring,message,secret,signer,random,metrics,limit);
            const double sign_seconds = seconds(start);
            double verify_seconds = 0, encode_seconds = 0, decode_seconds = 0;
            std::size_t encoded_size = 0;
            if (signature) {
                start = Clock::now();
                auto encoded = blrs::encode_signature(*signature,profile,encoding);
                encode_seconds = seconds(start);
                encoded_size = encoded.size();
                start = Clock::now();
                require(candidate.verify_research(ring,message,encoded), "generated signature did not verify");
                verify_seconds = seconds(start);
                start = Clock::now();
                const auto decoded = blrs::decode_signature(encoded,profile,encoding);
                decode_seconds = seconds(start);
                require(blrs::encode_signature(decoded,profile,encoding) == encoded, "codec round trip failed");
                if (check_mutations) mutations(candidate,ring,message,*signature);
                if (!output.empty() && run == 0) {
                    save(output+".signature.bin",encoded);
                    std::ofstream manifest_file(output+".manifest.json"); manifest_file << manifest << '\n';
                    if (!manifest_file) throw std::runtime_error("cannot write manifest");
                }
                ++successes;
            }
            if (run != 0) out << ",\n";
            out << "    {\"success\":" << (signature ? "true" : "false") << ",\"cache_state\":\"" << (run == 0 ? "cold" : "warm") << "\",\"attempts\":" << metrics.attempts
                << ",\"range_rejections\":" << metrics.range_rejections << ",\"base_rejections\":" << metrics.base_rejections
                << ",\"sampler_aborts\":" << metrics.sampler_aborts << ",\"sign_seconds\":" << sign_seconds
                << ",\"verify_seconds\":" << verify_seconds << ",\"encode_seconds\":" << encode_seconds
                << ",\"decode_seconds\":" << decode_seconds << ",\"fold_seconds\":" << metrics.fold_seconds
                << ",\"range_seconds\":" << metrics.range_seconds << ",\"compile_seconds\":" << metrics.compile_seconds
                << ",\"base_seconds\":" << metrics.base_seconds << ",\"signature_bytes\":" << encoded_size << '}';
            std::cerr << "Run " << run+1 << ": " << (signature ? "verified" : "attempt limit exhausted")
                << ", " << metrics.attempts << " attempts, sign " << sign_seconds << " s, verify " << verify_seconds << " s\n";
        }
        if (check_mutations) sign_and_link_tests(candidate,ring,secret);
        rusage usage{};
        if (getrusage(RUSAGE_SELF,&usage) != 0) throw std::runtime_error("cannot measure peak RSS");
        out << "\n  ],\n  \"successful_runs\":" << successes << ",\n  \"integration_tests\":" << (check_mutations ? "true" : "false") << ",\n  \"peak_process_rss_kib\":" << usage.ru_maxrss
            << ",\n  \"security_certified\":false\n}\n";
        if (!out) throw std::runtime_error("cannot write results");
        return successes == runs ? 0 : 2;
    } catch (const std::exception& error) {
        std::cerr << "Benchmark failed: " << error.what() << '\n';
        return 1;
    }
}
