// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"
#include "utils.hpp"

namespace evmone::state
{
class State
{
public:
    std::unordered_map<evmc::address, Account> accounts;
};

struct Tx
{
    bytes data;
    int64_t gas_limit;
    intx::uint256 gas_price;
    uint64_t nonce;
    evmc::address sender;
    evmc::address to;
    intx::uint256 value;
};

void transition(State& state, const Tx& tx, evmc_revision rev);

hash256 trie_hash(const State& state);
}  // namespace evmone::state
