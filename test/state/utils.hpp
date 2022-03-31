// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <cstring>

namespace evmone
{
using evmc::bytes;
using evmc::bytes_view;
using namespace evmc::literals;

/// Better than ethash::hash256 because has some additional handy constructors.
using hash256 = evmc::bytes32;

inline hash256 keccak256(bytes_view data) noexcept
{
    const auto eh = ethash::keccak256(std::data(data), std::size(data));
    hash256 h;
    std::memcpy(h.bytes, eh.bytes, sizeof(h));
    return h;
}

inline hash256 keccak256(const evmc::address& addr) noexcept
{
    return keccak256({addr.bytes, sizeof(addr)});
}

inline hash256 keccak256(const evmc::bytes32& h) noexcept
{
    return keccak256({h.bytes, sizeof(h)});
}

using evmc::address;
using evmc::from_hex;
using evmc::hex;

inline auto hex(const hash256& h) noexcept
{
    return hex({h.bytes, std::size(h.bytes)});
}

inline bytes to_bytes(std::string_view s)
{
    bytes b;
    b.reserve(std::size(s));
    for (const auto c : s)
        b.push_back(static_cast<uint8_t>(c));
    return b;
}

constexpr evmc_revision from_string(std::string_view s) noexcept
{
    if (s == "Frontier")
        return EVMC_FRONTIER;
    if (s == "Istanbul")
        return EVMC_ISTANBUL;
    if (s == "Berlin")
        return EVMC_BERLIN;
    if (s == "London")
        return EVMC_LONDON;
    assert(false && "unknown revision");
    __builtin_unreachable();
}
}  // namespace evmone
