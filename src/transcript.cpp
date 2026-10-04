#include "blrs/transcript.hpp"
#include "blrs/random.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cerrno>
#include <limits>
#include <memory>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

namespace blrs {

void SystemRandom::fill(std::span<std::uint8_t> bytes) {
#ifdef _WIN32
    while (!bytes.empty()) {
        const auto length = static_cast<ULONG>(std::min<std::size_t>(bytes.size(),
                                              std::numeric_limits<ULONG>::max()));
        if (BCryptGenRandom(nullptr, bytes.data(), length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            throw std::runtime_error("BCryptGenRandom failed");
        bytes = bytes.subspan(length);
    }
#else
    while (!bytes.empty()) {
        const auto count = getrandom(bytes.data(), bytes.size(), 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("getrandom failed");
        }
        if (count == 0) throw std::runtime_error("getrandom made no progress");
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
#endif
}

void append_u16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
}

void append_u32(Bytes& out, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        out.push_back(static_cast<std::uint8_t>(value >> shift));
}

Bytes shake256(std::span<const std::uint8_t> bytes, std::size_t length) {
    const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_shake256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), bytes.data(), bytes.size()) != 1)
        throw std::runtime_error("SHAKE256 initialization failed");
    Bytes output(length);
    if (EVP_DigestFinalXOF(context.get(), output.data(), output.size()) != 1)
        throw std::runtime_error("SHAKE256 output failed");
    return output;
}

void append_frame(Bytes& prefix, std::string_view label, std::span<const std::uint8_t> bytes) {
    if (label.size() > std::numeric_limits<std::uint32_t>::max() ||
        std::any_of(label.begin(), label.end(), [](unsigned char c) { return c > 127; }))
        throw std::invalid_argument("frame label is not bounded ASCII");
    append_u32(prefix, static_cast<std::uint32_t>(label.size()));
    prefix.insert(prefix.end(), label.begin(), label.end());
    append_u64(prefix, bytes.size());
    prefix.insert(prefix.end(), bytes.begin(), bytes.end());
}

Bytes frame(std::string_view label, std::span<const std::uint8_t> bytes) {
    Bytes result;
    append_frame(result, label, bytes);
    return result;
}

Identifier framed_identifier(std::string_view label, std::span<const std::uint8_t> bytes) {
    const auto output = shake256(frame(label, bytes), 64);
    Identifier result{};
    std::copy(output.begin(), output.end(), result.begin());
    return result;
}

} // namespace blrs
