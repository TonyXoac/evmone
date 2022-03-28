// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <test/state/state.hpp>

#include <nlohmann/json.hpp>
#include <fstream>

namespace json = nlohmann;

using namespace evmone;
using namespace evmone::state;

template <typename T>
T from_json(const json::json& j) = delete;

template <>
address from_json<address>(const json::json& j)
{
    return evmc::literals::internal::from_hex<address>(j.get<std::string>().c_str() + 2);
}

template <>
hash256 from_json<hash256>(const json::json& j)
{
    return evmc::literals::internal::from_hex<hash256>(j.get<std::string>().c_str() + 2);
}

template <>
intx::uint256 from_json<intx::uint256>(const json::json& j)
{
    return intx::from_string<intx::uint256>(j.get<std::string>().c_str());
}

template <>
bytes from_json<bytes>(const json::json& j)
{
    return from_hex(j.get<std::string>());
}

template <>
int from_json<int>(const json::json& j)
{
    return std::stoi(j.get<std::string>(), nullptr, 16);
}

template <>
int64_t from_json<int64_t>(const json::json& j)
{
    return static_cast<int64_t>(std::stoll(j.get<std::string>(), nullptr, 16));
}

template <>
uint64_t from_json<uint64_t>(const json::json& j)
{
    return static_cast<uint64_t>(std::stoull(j.get<std::string>(), nullptr, 16));
}

static void run_state_test(const json::json& j)
{
    SCOPED_TRACE(j.begin().key());
    const auto& _t = j.begin().value();
    const auto& tr = _t["transaction"];
    const auto& pre = _t["pre"];

    state::State pre_state;

    for (const auto& [j_addr, j_acc] : pre.items())
    {
        const auto addr = from_json<address>(j_addr);
        auto& acc = pre_state.accounts[addr];
        acc.balance = from_json<intx::uint256>(j_acc["balance"]);
        acc.nonce = from_json<int>(j_acc["nonce"]);
        acc.code = from_json<bytes>(j_acc["code"]);
    }

    state::Tx tx;
    // Common transaction part.
    if (tr.contains("gasPrice"))
    {
        tx.max_gas_price = from_json<intx::uint256>(tr["gasPrice"]);
        tx.max_priority_gas_price = tx.max_gas_price;
    }
    else
    {
        tx.max_gas_price = from_json<intx::uint256>(tr["maxFeePerGas"]);
        tx.max_priority_gas_price = from_json<intx::uint256>(tr["maxPriorityFeePerGas"]);
    }
    tx.nonce = from_json<uint64_t>(tr["nonce"]);
    tx.sender = from_json<evmc::address>(tr["sender"]);
    tx.to = from_json<evmc::address>(tr["to"]);

    evmc::VM vm{evmc_create_evmone(), {{"O", "0"}}};

    BlockInfo block;
    const auto& env = _t["env"];
    block.gas_limit = from_json<int64_t>(env["currentGasLimit"]);
    block.coinbase = from_json<evmc::address>(env["currentCoinbase"]);
    block.base_fee = from_json<uint64_t>(env["currentBaseFee"]);
    block.difficulty = from_json<evmc::uint256be>(env["currentDifficulty"]);
    block.number = from_json<int64_t>(env["currentNumber"]);
    block.timestamp = from_json<int64_t>(env["currentTimestamp"]);

    for (const auto& [rev_name, posts] : _t["post"].items())
    {
        SCOPED_TRACE(rev_name);
        const auto rev = from_string(rev_name);
        int i = 0;
        for (const auto& [_, post] : posts.items())
        {
            const auto expected_state_hash = from_json<hash256>(post["hash"]);
            const auto& indexes = post["indexes"];
            tx.data = from_json<bytes>(tr["data"][indexes["data"].get<size_t>()]);
            tx.gas_limit = from_json<int64_t>(tr["gasLimit"][indexes["gas"].get<size_t>()]);
            tx.value = from_json<intx::uint256>(tr["value"][indexes["value"].get<size_t>()]);

            auto state = pre_state;
            state::transition(state, block, tx, rev, vm);

            EXPECT_EQ(state::trie_hash(state), expected_state_hash) << rev_name << " " << i;
            ++i;
        }
    }
}

TEST(state, state_tests)
{
    const std::string root_dir = "/home/chfast/Projects/ethereum/tests/GeneralStateTests";
    const std::string test_files[] = {
        // "stExample/accessListExample.json",
        "stExample/add11.json",
        "stExample/add11_yml.json",
        // "stExample/basefeeExample.json",  // Requires EIP-1559 tx
        // "stExample/eip1559.json",         // Requires EIP-1559 tx
        "stExample/indexesOmitExample.json",
        // "stExample/invalidTr.json",
        "stExample/labelsExample.json",
        "stExample/rangesExample.json",
        // "stExample/solidityExample.json",  // Requires CALL
        "stExample/yulExample.json",
    };

    for (const auto& test_file : test_files)
    {
        json::json j;
        std::ifstream{root_dir + '/' + test_file} >> j;
        SCOPED_TRACE(test_file);
        run_state_test(j);
    }
}
