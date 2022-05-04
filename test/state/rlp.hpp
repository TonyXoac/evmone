// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

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

    if (l <= 0xff)
        return bytes{0xb7 + 1, static_cast<uint8_t>(l)} + bytes{data};

    if (l <= 0xffff)
        return bytes{0xb7 + 2, static_cast<uint8_t>(l >> 8), static_cast<uint8_t>(l)} + bytes{data};

    assert(l <= 0xffffff);
    return bytes{0xb7 + 3, static_cast<uint8_t>(l >> 16), static_cast<uint8_t>(l >> 8),
               static_cast<uint8_t>(l)} +
           bytes{data};
}

inline bytes_view trim(bytes_view b) noexcept
{
    b.remove_prefix(std::min(b.find_first_not_of(uint8_t{0x00}), b.size()));
    return b;
}

inline bytes_view trim(const evmc::uint256be& v) noexcept
{
    return trim({v.bytes, sizeof(v)});
}

inline bytes string(const hash256& b)
{
    return string({b.bytes, sizeof(b)});
}

inline bytes string(uint64_t x)
{
    uint8_t b[sizeof(x)];
    intx::be::store(b, x);
    return string(trim({b, sizeof(b)}));
}

inline bytes list_raw(bytes_view items)
{
    const auto items_len = items.size();
    assert(items_len <= 0xffffff);
    bytes r;
    if (items_len <= 55)
        r = {static_cast<uint8_t>(0xc0 + items_len)};
    else if (items_len <= 0xff)
        r = {0xf7 + 1, static_cast<uint8_t>(items_len)};
    else if (items_len <= 0xffff)
        r = {0xf7 + 2, static_cast<uint8_t>(items_len >> 8), static_cast<uint8_t>(items_len)};
    else if (items_len <= 0xffffff)
        r = {0xf7 + 3, static_cast<uint8_t>(items_len >> 16), static_cast<uint8_t>(items_len >> 8),
            static_cast<uint8_t>(items_len)};
    r += items;
    return r;
}

template <typename InputIterator>
inline bytes list_raw(InputIterator begin, InputIterator end)
{
    bytes content;
    for (auto it = begin; it != end; ++it)
        content += string(*it);
    return list_raw(content);
}

template <typename... Items>
inline bytes list(const Items&... items)
{
    return list_raw((string(items) + ...));
}

}  // namespace evmone::rlp
