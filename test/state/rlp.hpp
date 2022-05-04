// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "utils.hpp"
#include <cassert>

namespace evmone::rlp
{
namespace internal
{
template <uint8_t ShortBase, uint8_t LongBase>
inline bytes encode_length(size_t l)
{
    static constexpr auto short_cutoff = 55;
    static_assert(ShortBase + short_cutoff <= 0xff);
    assert(l <= 0xffffff);

    if (l <= short_cutoff)
        return {static_cast<uint8_t>(ShortBase + l)};
    else if (const auto l0 = static_cast<uint8_t>(l); l <= 0xff)
        return {LongBase + 1, l0};
    else if (const auto l1 = static_cast<uint8_t>(l >> 8); l <= 0xffff)
        return {LongBase + 2, l1, l0};
    else
        return {LongBase + 3, static_cast<uint8_t>(l >> 16), l1, l0};
}
}  // namespace internal

inline bytes string(bytes_view data)
{
    static constexpr uint8_t short_base = 0x80;
    if (data.size() == 1 && data[0] < short_base)
        return {data[0]};

    auto r = internal::encode_length<short_base, 0xb7>(data.size());
    r += data;
    return r;
}

inline bytes_view trim(bytes_view b) noexcept
{
    b.remove_prefix(std::min(b.find_first_not_of(uint8_t{0x00}), b.size()));
    return b;
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

inline bytes string(const intx::uint256& x)
{
    uint8_t b[sizeof(x)];
    intx::be::store(b, x);
    return string(trim({b, sizeof(b)}));
}

inline bytes list_raw(bytes_view items)
{
    auto r = internal::encode_length<0xc0, 0xf7>(items.size());
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
