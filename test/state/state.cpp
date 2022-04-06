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

int64_t compute_access_list_cost(const AccessList& access_list) noexcept
{
    static constexpr auto storage_key_cost = 1900;
    static constexpr auto address_cost = 2400;

    int64_t cost = 0;
    for (const auto& a : access_list)
        cost += address_cost + static_cast<int64_t>(a.second.size()) * storage_key_cost;
    return cost;
}

int64_t compute_tx_intrinsic_cost(evmc_revision rev, const Tx& tx) noexcept
{
    static constexpr auto call_tx_cost = 21000;
    return call_tx_cost + compute_tx_data_cost(rev, tx.data) +
           compute_access_list_cost(tx.access_list);
}
}  // namespace

bool transition(State& state, const BlockInfo& block, const Tx& tx, evmc_revision rev, evmc::VM& vm)
{
    assert(block.gas_limit >= tx.gas_limit);
    assert(state.accounts[tx.sender].balance >=
           tx.gas_limit * tx.max_gas_price);  // FIXME: Should be effective_gas_price
    const auto execution_gas_limit = tx.gas_limit - compute_tx_intrinsic_cost(rev, tx);
    if (execution_gas_limit < 0)
        return false;

    state.accounts[tx.sender].nonce += 1;

    const auto state_snapshot = state;

    state.accounts[tx.sender].balance -= tx.value;
    state.accounts[tx.to].balance += tx.value;

    StateHost host{rev, vm, state, block, tx};

    bytes_view code = state.accounts[tx.to].code;
    const auto value_be = intx::be::store<evmc::uint256be>(tx.value);

    assert(tx.to != evmc::address{});
    evmc_message msg{EVMC_CALL, 0, 0, execution_gas_limit, tx.to, tx.sender, tx.data.data(),
        tx.data.size(), value_be, {}, tx.to};
    const auto result = vm.execute(host, rev, msg, code.data(), code.size());
    const auto gas_left = result.gas_left;

    if (result.status_code != EVMC_SUCCESS)
        state = state_snapshot;

    auto gas_used = tx.gas_limit - gas_left;

    const auto max_refund_quotient = rev >= EVMC_LONDON ? 5 : 2;
    const auto refund_limit = gas_used / max_refund_quotient;
    const auto refund_raw = (result.status_code == EVMC_SUCCESS) ? host.get_refund() : 0;
    const auto refund = std::min(refund_raw, refund_limit);
    gas_used -= refund;

    const auto base_fee = (rev >= EVMC_LONDON) ? block.base_fee : 0;

    assert(tx.max_gas_price >= base_fee);
    assert(tx.max_gas_price >= tx.max_priority_gas_price);

    const auto priority_gas_price =
        std::min(tx.max_priority_gas_price, tx.max_gas_price - base_fee);
    const auto effective_gas_price = base_fee + priority_gas_price;

    const auto sender_fee = gas_used * effective_gas_price;
    const auto producer_pay = gas_used * priority_gas_price;

    assert(state.accounts[tx.sender].balance >= sender_fee);
    state.accounts[tx.sender].balance -= sender_fee;
    state.accounts[block.coinbase].balance += producer_pay;

    // Apply destructs.
    assert(host.get_destructs().empty() || result.status_code == EVMC_SUCCESS);
    for (const auto& addr : host.get_destructs())
        state.accounts.erase(addr);

    // Pretend all accounts are touched and erase empty ones.
    for (auto it = state.accounts.begin(); it != state.accounts.end();)
    {
        const auto& acc = it->second;
        if (acc.balance == 0 && acc.nonce == 0 && acc.code.empty())
            state.accounts.erase(it++);
        else
            ++it;
    }
    return true;
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
        // Skip zero values which mean "delete".
        // TODO: This probably should be handled in Host.
        if (is_zero(value.value))
            continue;

        const auto xkey = keccak256(key);
        const auto xvalue = rlp::string(rlp::trim(value.value));
        trie.insert(xkey, xvalue);
    }
    return trie.hash();
}
}  // namespace evmone::state
