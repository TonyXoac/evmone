// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "utils.hpp"
#include <iostream>
#include <unordered_set>

namespace evmone::state
{
class State
{
public:
    std::unordered_map<evmc::address, Account> accounts;
};

struct BlockInfo
{
    int64_t number;
    int64_t timestamp;
    int64_t gas_limit;
    evmc::address coinbase;
    evmc::uint256be difficulty;
    evmc::bytes32 chain_id;
    uint64_t base_fee;
};

using AccessList = std::vector<std::pair<evmc::address, std::vector<evmc::bytes32>>>;

struct Tx
{
    bytes data;
    int64_t gas_limit;
    intx::uint256 max_gas_price;
    intx::uint256 max_priority_gas_price;
    uint64_t nonce;
    evmc::address sender;
    evmc::address to;
    intx::uint256 value;
    AccessList access_list;
};

// TODO: Cleanup.
using evmc::bytes32;
using evmc::uint256be;

class StateHost : public evmc::Host
{
    evmc_revision m_rev;
    evmc::VM& m_vm;
    State& m_state;
    const BlockInfo& m_block;
    const Tx& m_tx;
    std::unordered_set<evmc::address> m_accessed_addresses;

public:
    explicit StateHost(evmc_revision rev, evmc::VM& vm, State& state, const BlockInfo& block,
        const Tx& tx) noexcept
      : m_rev{rev}, m_vm{vm}, m_state{state}, m_block{block}, m_tx{tx}
    {}

    bool account_exists(const address& addr) const noexcept override
    {
        return m_state.accounts.count(addr) != 0;
    }

    bytes32 get_storage(const address& addr, const bytes32& key) const noexcept override
    {
        const auto account_iter = m_state.accounts.find(addr);
        if (account_iter == m_state.accounts.end())
            return {};

        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end())
            return storage_iter->second.value;
        return {};
    }

    evmc_storage_status set_storage(
        const address& addr, const bytes32& key, const bytes32& value) noexcept override
    {
        // Get the reference to the old value.
        // This will create the account in case it was not present.
        // This is convenient for unit testing and standalone EVM execution to preserve the
        // storage values after the execution terminates.
        auto& old = m_state.accounts[addr].storage[key];

        // Follow https://eips.ethereum.org/EIPS/eip-1283 specification.
        // WARNING! This is not complete implementation as refund is not handled here.

        if (old.value == value)
            return EVMC_STORAGE_UNCHANGED;

        evmc_storage_status status{};
        if (!old.dirty)
        {
            old.dirty = true;
            if (!old.value)
                status = EVMC_STORAGE_ADDED;
            else if (value)
                status = EVMC_STORAGE_MODIFIED;
            else
                status = EVMC_STORAGE_DELETED;
        }
        else
            status = EVMC_STORAGE_MODIFIED_AGAIN;

        old.value = value;
        return status;
    }

    uint256be get_balance(const address& addr) const noexcept override
    {
        const auto it = m_state.accounts.find(addr);
        if (it == m_state.accounts.end())
            return {};

        return intx::be::store<uint256be>(it->second.balance);
    }

    size_t get_code_size(const address& addr) const noexcept override
    {
        const auto it = m_state.accounts.find(addr);
        if (it == m_state.accounts.end())
            return 0;
        return it->second.code.size();
    }

    bytes32 get_code_hash(const address& addr) const noexcept override
    {
        const auto it = m_state.accounts.find(addr);
        if (it == m_state.accounts.end())
            return {};
        return it->second.codehash;
    }

    size_t copy_code(const address& addr, size_t code_offset, uint8_t* buffer_data,
        size_t buffer_size) const noexcept override
    {
        const auto it = m_state.accounts.find(addr);
        if (it == m_state.accounts.end())
            return 0;

        const auto& code = it->second.code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    void selfdestruct(const address& addr, const address& beneficiary) noexcept override
    {
        (void)addr;
        (void)beneficiary;
        assert(false && "not implemented");
    }

    evmc::result call(const evmc_message& msg) noexcept override
    {
        std::cout << "CALL " << msg.kind << "\n"
                  << "  gas: " << msg.gas << "\n"
                  << "  code: " << hex({msg.code_address.bytes, sizeof(msg.code_address)}) << "\n";

        assert(msg.kind != EVMC_CREATE2);
        if (msg.kind == EVMC_CREATE)
        {
            auto create_msg = msg;
            create_msg.input_data = nullptr;
            create_msg.input_size = 0;
            auto result = m_vm.execute(*this, m_rev, create_msg, msg.input_data, msg.input_size);
            std::cout << "- RESULT " << result.status_code << "\n"
                      << "  gas: " << result.gas_left << "\n";
            return result;
        }

        const auto& code = m_state.accounts[msg.code_address].code;
        const auto state_snapshot = m_state;
        auto result = m_vm.execute(*this, m_rev, msg, code.data(), code.size());
        std::cout << "- RESULT " << result.status_code << "\n"
                  << "  gas: " << result.gas_left << "\n";
        if (result.status_code != EVMC_SUCCESS)
            m_state = state_snapshot;
        return result;
    }

    evmc_tx_context get_tx_context() const noexcept override
    {
        const auto priority_gas_price =
            std::min(m_tx.max_priority_gas_price, m_tx.max_gas_price - m_block.base_fee);
        const auto effective_gas_price = m_block.base_fee + priority_gas_price;

        return evmc_tx_context{
            intx::be::store<uint256be>(effective_gas_price),
            m_tx.sender,
            m_block.coinbase,
            m_block.number,
            m_block.timestamp,
            m_block.gas_limit,
            m_block.difficulty,
            m_block.chain_id,
            evmc::uint256be{m_block.base_fee},
        };
    }

    bytes32 get_block_hash(int64_t block_number) const noexcept override
    {
        (void)block_number;
        assert(false && "not implemented");
        return {};
    }

    void emit_log(const address& addr, const uint8_t* data, size_t data_size,
        const bytes32 topics[], size_t topics_count) noexcept override
    {
        (void)addr;
        (void)data;
        (void)data_size;
        (void)topics;
        (void)topics_count;
        // FIXME: Store logs.
    }

    evmc_access_status access_account(const address& addr) noexcept override
    {
        // Accessing precompiled contracts is always warm.
        if (addr >= 0x0000000000000000000000000000000000000001_address &&
            addr <= 0x0000000000000000000000000000000000000009_address)
            return EVMC_ACCESS_WARM;

        if (m_accessed_addresses.count(addr) != 0)
            return EVMC_ACCESS_WARM;

        m_accessed_addresses.insert(addr);
        return EVMC_ACCESS_COLD;
    }

    evmc_access_status access_storage(const address& addr, const bytes32& key) noexcept override
    {
        // Check tx access list.
        for (const auto& [a, storage_keys] : m_tx.access_list)
        {
            if (a == addr && std::count(storage_keys.begin(), storage_keys.end(), key) != 0)
                return EVMC_ACCESS_WARM;
        }

        auto& value = m_state.accounts[addr].storage[key];
        const auto access_status = value.access_status;
        value.access_status = EVMC_ACCESS_WARM;
        return access_status;
    }
};

[[nodiscard]] bool transition(
    State& state, const BlockInfo& block, const Tx& tx, evmc_revision rev, evmc::VM& vm);

hash256 trie_hash(const State& state);

hash256 trie_hash(const std::unordered_map<evmc::bytes32, evmc::storage_value>& storage);
}  // namespace evmone::state
