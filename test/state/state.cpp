// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "state.hpp"
#include "trie.hpp"
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>

namespace evmone::state
{
namespace
{
int64_t compute_tx_data_cost(evmc_revision rev, bytes_view data) noexcept
{
    constexpr int64_t zero_byte_cost = 4;
    const int64_t nonzero_byte_cost = rev >= EVMC_ISTANBUL ? 16 : 68;
    int64_t cost = 0;
    for (const auto b : data)
        cost += (b == 0) ? zero_byte_cost : nonzero_byte_cost;
    return cost;
}
}  // namespace

void transition(State& state, const BlockInfo& block, const Tx& tx, evmc_revision rev, evmc::VM& vm)
{
    state.accounts[tx.sender].nonce += 1;

    state.accounts[tx.sender].balance -= tx.value;
    state.accounts[tx.to].balance += tx.value;

    StateHost host{state};

    bytes_view code = state.accounts[tx.to].code;
    const auto value_be = intx::be::store<evmc::uint256be>(tx.value);

    const auto data_gas = compute_tx_data_cost(rev, tx.data);

    evmc_message msg{EVMC_CALL, 0, 0, tx.gas_limit, tx.to, tx.sender, tx.data.data(),
        tx.data.size(), value_be, {}, tx.to};
    const auto gas_left = vm.execute(host, rev, msg, code.data(), code.size()).gas_left;

    const auto gas_used = tx.gas_limit - gas_left + 21000 + data_gas;
    const auto sender_fee = gas_used * tx.gas_price;

    const auto base_fee = (rev >= EVMC_LONDON) ? block.base_fee : 0;
    assert(tx.gas_price >= base_fee);
    const auto priority_fee = tx.gas_price - base_fee;
    assert(priority_fee >= 0);
    const auto producer_pay = gas_used * priority_fee;

    assert(state.accounts[tx.sender].balance >= sender_fee);
    state.accounts[tx.sender].balance -= sender_fee;
    state.accounts[block.coinbase].balance += producer_pay;
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
