// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "trie.hpp"
#include "rlp.hpp"

namespace evmone::state
{
void Trie::insert(const Path& k, bytes&& v)
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
        branch->children[newIdx] = std::make_unique<Trie>(leaf(k.tail(diffidx + 1), std::move(v)));
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
        branch->children[newIdx] = std::make_unique<Trie>(leaf(k.tail(diffidx + 1), std::move(v)));

        m_path = m_path.head(diffidx);
        break;
    }

    default:
        assert(false);
    }
}

hash256 Trie::hash() const
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

}  // namespace evmone::state
