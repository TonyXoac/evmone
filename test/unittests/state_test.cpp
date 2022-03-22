// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>
#include <test/state/trie.hpp>
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
    return evmc::literals::internal::from_hex<address>(j.get<std::string>().c_str());
}

template <>
hash256 from_json<hash256>(const json::json& j)
{
    return evmc::literals::internal::from_hex<hash256>(j.get<std::string>().c_str());
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

TEST(state, load_json)
{
    const auto file = "/home/chfast/Projects/ethereum/tests/GeneralStateTests/stExample/add11.json";
    std::ifstream in{file};
    json::json j;
    in >> j;

    const auto& _t = j["add11"];
    const auto& tr = _t["transaction"];
    const auto& pre = _t["pre"];

    state::State state;

    for (const auto& [j_addr, j_acc] : pre.items())
    {
        const auto addr = from_json<address>(j_addr);
        auto& acc = state.accounts[addr];
        acc.balance = from_json<hash256>(j_acc["balance"]);
        acc.nonce = from_json<int>(j_acc["nonce"]);
        acc.code = from_json<bytes>(j_acc["code"]);
    }

    const auto coinbase = 0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba_address;
    const auto origin = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address;
    const auto recipient = 0x095e7baea6a6c7c4c2dfeb977efac326af552d87_address;

    EXPECT_EQ(state.accounts[coinbase].balance.bytes[0], 0);

    EXPECT_EQ(state.accounts[origin].balance.bytes[0], 0);

    EXPECT_EQ(state.accounts[recipient].balance.bytes[0], 0);

    EXPECT_EQ(tr["data"][0].get<std::string>(), "0x");
}
