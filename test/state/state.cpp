// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "trie.hpp"
#include <evmone/baseline.hpp>

namespace evmone::state
{
void transition(State& state, const Tx& tx, evmc_revision rev)
{
    (void)state;
    (void)tx;
    (void)rev;
}

hash256 trie_hash(const State& state)
{
    Trie trie;
    for (const auto& [addr, acc] : state.accounts)
    {
        const auto xkey = keccak256(addr);
        const auto xval = rlp::encode(acc);
        trie.insert(Path{{xkey.bytes, sizeof(xkey)}}, xval);
    }
    return trie.hash();
}
}  // namespace evmone::state
