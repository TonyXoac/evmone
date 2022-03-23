// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "trie.hpp"
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>

namespace evmone::state
{
void transition(State& state, const Tx& tx, evmc_revision rev)
{
    // TODO: VM should be passed as parameter.
    evmc::VM vm{evmc_create_evmone(), {{"O", "0"}}};

    StateHost host{state};

    bytes_view code = state.accounts[tx.to].code;
    const auto value_be = intx::be::store<evmc::uint256be>(tx.value);
    evmc_message msg{EVMC_CALL, 0, 0, tx.gas_limit, tx.to, tx.sender, tx.data.data(),
        tx.data.size(), value_be, {}, tx.to};
    vm.execute(host, rev, msg, code.data(), code.size());
}

hash256 trie_hash(const State& state)
{
    Trie trie;
    for (const auto& [addr, acc] : state.accounts)
    {
        const auto xkey = keccak256(addr);

        const auto storage_hash = trie_hash(acc.storage);
        const auto balance_bytes = intx::be::store<evmc::uint256be>(acc.balance);
        const auto code_hash = keccak256(acc.code);
        const auto xacc = rlp::list(acc.nonce, rlp::trim(balance_bytes), storage_hash, code_hash);

        trie.insert(Path{{xkey.bytes, sizeof(xkey)}}, xacc);
    }
    return trie.hash();
}

hash256 trie_hash(const std::unordered_map<evmc::bytes32, evmc::storage_value>& storage)
{
    Trie trie;
    for (const auto& [key, value] : storage)
    {
        const auto xkey = keccak256(key);
        const auto xvalue = rlp::string(rlp::trim(value.value));
        trie.insert(xkey, xvalue);
    }
    return trie.hash();
}
}  // namespace evmone::state
