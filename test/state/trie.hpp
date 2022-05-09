// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "rlp.hpp"
#include <algorithm>
#include <memory>

namespace evmone::state
{
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

    void insert(const Path& k, bytes&& v)
    {
        switch (m_type)
        {
        case NodeType::null:
            *this = leaf(k, std::move(v));
            break;

        case NodeType::branch:
        {
            assert(m_path.num_nibbles == 0);
            const auto idx = k.nibbles[0];
            auto& child = children[idx];
            if (!child)
                child = std::make_unique<Trie>(leaf(k.tail(1), std::move(v)));
            else
                child->insert(k.tail(1), std::move(v));
            break;
        }

        case NodeType::ext:
        {
            const auto diffidx = diff_index(m_path, k);

            if (diffidx == m_path.num_nibbles)
            {
                // Go into child.
                return children[0]->insert(k.tail(diffidx), std::move(v));
            }

            std::unique_ptr<Trie> n;
            if (diffidx < m_path.num_nibbles - 1)
                n = std::make_unique<Trie>(ext(m_path.tail(diffidx + 1), std::move(children[0])));
            else
                n = std::move(children[0]);

            Trie* branch = nullptr;
            if (diffidx == 0)
            {
                branch = this;
                branch->m_type = NodeType::branch;
            }
            else
            {
                branch = (children[0] = std::make_unique<Trie>()).get();
                branch->m_type = NodeType::branch;
            }

            const auto origIdx = m_path.nibbles[diffidx];
            const auto newIdx = k.nibbles[diffidx];

            branch->children[origIdx] = std::move(n);
            branch->children[newIdx] =
                std::make_unique<Trie>(leaf(k.tail(diffidx + 1), std::move(v)));
            m_path = m_path.head(diffidx);
            break;
        }

        case NodeType::leaf:
        {
            // TODO: Add assert for k == key.
            const auto diffidx = diff_index(m_path, k);

            Trie* branch = nullptr;
            if (diffidx == 0)  // Convert into a branch.
            {
                m_type = NodeType::branch;
                branch = this;
            }
            else
            {
                m_type = NodeType::ext;
                branch = (children[0] = std::make_unique<Trie>()).get();
                branch->m_type = NodeType::branch;
            }

            const auto origIdx = m_path.nibbles[diffidx];
            branch->children[origIdx] =
                std::make_unique<Trie>(leaf(m_path.tail(diffidx + 1), std::move(m_value)));

            const auto newIdx = k.nibbles[diffidx];
            assert(origIdx != newIdx);
            branch->children[newIdx] =
                std::make_unique<Trie>(leaf(k.tail(diffidx + 1), std::move(v)));

            m_path = m_path.head(diffidx);
            break;
        }

        default:
            assert(false);
        }
    }

public:
    Trie() = default;

    void insert(bytes_view key, bytes&& value) { insert(Path{key}, std::move(value)); }

    [[nodiscard]] hash256 hash() const
    {
        hash256 r{};
        switch (m_type)
        {
        case NodeType::null:
            return emptyTrieHash;
        case NodeType::leaf:
        {
            const auto node = rlp::tuple(m_path.encode(false), m_value);
            r = keccak256(node);
            break;
        }
        case NodeType::branch:
        {
            assert(m_path.num_nibbles == 0);

            // Temporary storage for children hashes.
            // The `bytes` type could be used instead, but this way dynamic allocation is avoided.
            hash256 children_hashes[num_children];

            // Views of children hash bytes. Additional item for hash list
            // terminator (always empty). Does not seem needed for correctness,
            // but this is what the spec says.
            bytes_view children_hash_bytes[num_children + 1];

            for (size_t i = 0; i < num_children; ++i)
            {
                if (children[i])
                {
                    children_hashes[i] = children[i]->hash();
                    children_hash_bytes[i] = children_hashes[i];
                }
            }

            r = keccak256(rlp::encode(children_hash_bytes));
            break;
        }
        case NodeType::ext:
        {
            const auto branch = children[0].get();
            assert(branch != nullptr);
            assert(branch->m_type == NodeType::branch);
            r = keccak256(rlp::tuple(m_path.encode(true), branch->hash()));
            break;
        }
        default:
            assert(false);
        }

        return r;
    }
};

}  // namespace evmone::state
