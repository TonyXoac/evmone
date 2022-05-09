// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "utils.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <memory>

namespace evmone::state
{
constexpr auto emptyTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

/// Trie path (key)
struct Path
{
    size_t num_nibbles;  // TODO: Can be converted to uint8_t.
    uint8_t nibbles[64];

    explicit Path(bytes_view k) noexcept : num_nibbles(2 * std::size(k))
    {
        assert(num_nibbles <= 64);
        size_t i = 0;
        for (const auto b : k)
        {
            nibbles[i++] = b >> 4;
            nibbles[i++] = b & 0x0f;
        }
    }

    [[nodiscard]] Path tail(size_t index) const
    {
        assert(index <= num_nibbles);
        Path p{{}};
        p.num_nibbles = num_nibbles - index;
        std::memcpy(p.nibbles, &nibbles[index], p.num_nibbles);
        return p;
    }

    [[nodiscard]] Path head(size_t size) const
    {
        assert(size < num_nibbles);
        Path p{{}};
        p.num_nibbles = size;
        std::memcpy(p.nibbles, nibbles, size);
        return p;
    }

    [[nodiscard]] bytes encode(bool extended) const
    {
        bytes bs;
        const auto is_even = num_nibbles % 2 == 0;
        if (is_even)
            bs.push_back(0x00);
        else
            bs.push_back(0x10 | nibbles[0]);
        for (size_t i = is_even ? 0 : 1; i < num_nibbles; ++i)
        {
            const auto h = nibbles[i++];
            const auto l = nibbles[i];
            assert(h <= 0x0f);
            assert(l <= 0x0f);
            bs.push_back(uint8_t((h << 4) | l));
        }
        if (!extended)
            bs[0] |= 0x20;
        return bs;
    }
};


/// Insert-only Trie implementation for getting the root hash out of (key, value) pairs.
/// Based on StackTrie from go-ethereum.
class Trie
{
    enum class NodeType : uint8_t
    {
        null,
        leaf,
        ext,
        branch
    };

    static constexpr uint8_t num_children = 16;

    NodeType m_type{NodeType::null};
    Path m_path{{}};
    bytes m_value;
    std::unique_ptr<Trie> children[num_children];

    Trie(NodeType type, const Path& path, bytes&& value = {}) noexcept
      : m_type{type}, m_path{path}, m_value{std::move(value)}
    {}

    /// Named constructor for a leaf node.
    static Trie leaf(const Path& k, bytes&& v) noexcept
    {
        return {NodeType::leaf, k, std::move(v)};
    }

    /// Named constructor for an extended node.
    static Trie ext(const Path& k, std::unique_ptr<Trie> child) noexcept
    {
        Trie node{NodeType::ext, k};
        node.children[0] = std::move(child);
        return node;
    }

    static size_t diff_index(const Path& p1, const Path& p2) noexcept
    {
        assert(p1.num_nibbles <= p2.num_nibbles);
        return static_cast<size_t>(
            std::mismatch(p1.nibbles, p1.nibbles + p1.num_nibbles, p2.nibbles).first - p1.nibbles);
    }

    void insert(const Path& k, bytes&& v);

public:
    Trie() = default;

    inline void insert(bytes_view key, bytes&& value) { insert(Path{key}, std::move(value)); }

    [[nodiscard]] hash256 hash() const;
};

}  // namespace evmone::state
