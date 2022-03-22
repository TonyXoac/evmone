// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "utils.hpp"
#include <cassert>

namespace evmone::rlp
{
inline bytes string(bytes_view data)
{
    const auto l = std::size(data);
    if (l == 1 && data[0] <= 0x7f)
        return bytes{data[0]};
    if (l <= 55)
        return bytes{static_cast<uint8_t>(0x80 + l)} + bytes{data};

    assert(data.size() <= 0xff);
    return bytes{0xb7 + 1, static_cast<uint8_t>(l)} + bytes{data};
}

inline bytes_view trim(const evmc::uint256be& v)
{
    size_t i = 0;
    for (; i < sizeof(v); ++i)
    {
        if (v.bytes[i] != 0)
            break;
    }
    const size_t l = sizeof(v) - i;
    return {&v.bytes[i], l};
}

inline bytes string(const hash256& b)
{
    return string({b.bytes, sizeof(b)});
}

inline bytes string(int x)
{
    // TODO: Account::nonce should be uint64_t.
    uint8_t b[sizeof(x)];
    const auto be = __builtin_bswap32(static_cast<unsigned>(x));
    __builtin_memcpy(b, &be, sizeof(be));

    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b[i] != 0)
            break;
    }
    const size_t l = sizeof(b) - i;
    return string({&b[i], l});
}

template <typename... Items>
inline bytes list(const Items&... items)
{
    const bytes string_items[] = {string(items)...};
    size_t items_len = 0;
    for (const auto& s : string_items)
        items_len += std::size(s);
    assert(items_len <= 0xff);
    auto r = (items_len <= 55) ? bytes{static_cast<uint8_t>(0xc0 + items_len)} :
                                 bytes{0xf7 + 1, static_cast<uint8_t>(items_len)};
    for (const auto& s : string_items)
        r += s;
    return r;
}

inline bytes encode(const state::Account& a)
{
    assert(a.storage.empty());
    const auto balance_bytes = intx::be::store<evmc::uint256be>(a.balance);
    const auto code_hash = keccak256(a.code);
    return rlp::list(a.nonce, rlp::trim(balance_bytes), state::emptyTrieHash, code_hash);
}
}  // namespace evmone::rlp
