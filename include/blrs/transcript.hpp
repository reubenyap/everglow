#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace blrs {

using Bytes = std::vector<std::uint8_t>;
using Identifier = std::array<std::uint8_t, 64>;

Bytes shake256(std::span<const std::uint8_t> bytes, std::size_t length);
Bytes frame(std::string_view label, std::span<const std::uint8_t> bytes);
void append_frame(Bytes& prefix, std::string_view label, std::span<const std::uint8_t> bytes);
Identifier framed_identifier(std::string_view label, std::span<const std::uint8_t> bytes);
void append_u16(Bytes& out, std::uint16_t value);
void append_u32(Bytes& out, std::uint32_t value);
void append_u64(Bytes& out, std::uint64_t value);

} // namespace blrs
