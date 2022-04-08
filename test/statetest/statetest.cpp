
#include "../state/state.hpp"
#include <evmone/evmone.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace json = nlohmann;

using namespace evmone;
using namespace evmone::state;
using namespace std::string_view_literals;

template <typename T>
T from_json(const json::json& j) = delete;

template <>
address from_json<address>(const json::json& j)
{
    const auto s = j.get<std::string>();
    if (s.empty())
        return {};
    assert(s.size() == 42);
    return evmc::literals::internal::from_hex<address>(s.c_str() + 2);
}

template <>
hash256 from_json<hash256>(const json::json& j)
{
    const auto bytes = from_hex(j.get<std::string>());
    assert(bytes.size() <= 32);
    hash256 h{};
    std::memcpy(&h.bytes[32 - bytes.size()], bytes.data(), bytes.size());
    return h;
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
        acc.nonce = from_json<uint64_t>(j_acc["nonce"]);
        acc.code = from_json<bytes>(j_acc["code"]);

        for (const auto& [j_key, j_value] : j_acc["storage"].items())
        {
            auto& slot = acc.storage[from_json<bytes32>(j_key)];
            const auto value = from_json<bytes32>(j_value);
            slot.orig = value;
            slot.current = value;
        }
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

    // TODO: Chain ID is expected to be 1.
    block.chain_id = {};
    block.chain_id.bytes[31] = 1;

    const auto access_lists_it = tr.find("accessLists");

    for (const auto& [rev_name, posts] : _t["post"].items())
    {
        // if (rev_name != "London")
        //     continue;

        SCOPED_TRACE(rev_name);
        const auto rev = from_string(rev_name);
        int i = 0;
        for (const auto& [_, post] : posts.items())
        {
            // if (i != 5)
            // {
            //     ++i;
            //     continue;
            // }
            const auto expected_state_hash = from_json<hash256>(post["hash"]);
            const auto& indexes = post["indexes"];
            const auto data_index = indexes["data"].get<size_t>();
            tx.data = from_json<bytes>(tr["data"][data_index]);
            tx.gas_limit = from_json<int64_t>(tr["gasLimit"][indexes["gas"].get<size_t>()]);
            tx.value = from_json<intx::uint256>(tr["value"][indexes["value"].get<size_t>()]);

            tx.access_list.clear();
            if (access_lists_it != tr.end())
            {
                for (const auto& [_2, a] : access_lists_it.value()[data_index].items())
                {
                    tx.access_list.push_back({from_json<evmc::address>(a["address"]), {}});
                    auto& storage_access_list = tx.access_list.back().second;
                    for (const auto& [_3, storage_key] : a["storageKeys"].items())
                        storage_access_list.push_back(from_json<bytes32>(storage_key));
                }
            }

            auto state = pre_state;

            const auto expect_tx_exception = post.contains("expectException");
            const auto tx_status = state::transition(state, block, tx, rev, vm);
            EXPECT_NE(tx_status, expect_tx_exception);

            std::ostringstream state_dump;

            state_dump << "--- " << rev_name << " " << i << "\n";
            for (const auto& [addr, acc] : state.accounts)
            {
                state_dump << evmc::hex({addr.bytes, sizeof(addr.bytes)}) << " [" << acc.nonce
                           << "]: " << to_string(acc.balance) << "\n";
                for (const auto& [k, v] : acc.storage)
                {
                    if (is_zero(v.current))
                        continue;
                    state_dump << "- " << evmc::hex({k.bytes, sizeof(k)}) << ": "
                               << evmc::hex({v.current.bytes, sizeof(v.current)}) << "\n";
                }
            }

            EXPECT_EQ(state::trie_hash(state), expected_state_hash) << state_dump.str();
            // FIXME: Check logs trie hash.
            ++i;
        }
    }
}

namespace fs = std::filesystem;

class StateTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit StateTest(fs::path json_test_file) : m_json_test_file{std::move(json_test_file)} {}

    void TestBody() override
    {
        json::json j;
        std::ifstream{m_json_test_file} >> j;
        run_state_test(j);
    }
};

int main(int argc, char* argv[])
{
    constexpr auto known_passing_tests =
        "stArgsZeroOneBalance.*:"
        // "stCallCodes.*:"
        "stCallCreateCallCodeTest.call*:"
        "stCreate2.CREATE2_Bounds*:"
        "stCreate2.call*:"
        "stCreateTest.*:"
        "stChainId.*:"
        // "stEIP2930.coinbaseT2:"
        // "stEIP2930.addressOpcodes:"
        "stEIP2930.transactionCosts:"
        "stExample.*:"
        "stMemoryTest.*:"
        "stRefundTest.*:"
        "stShift.*:"
        "stSLoadTest.*:"
        "stSStoreTest.sstore_*:"
        "stStackTests.*:"
        // "stStaticCall.static_call*:"
        "VMTests/*.*:"
        "-"
        "stArgsZeroOneBalance.*NonConst:"
        "stCreateTest.CREATE_HighNonceMinus1:"
        "stCreateTest.CREATE_EmptyContractWithStorageAndCallIt_0wei:"
        "stCreateTest.CREATE_EmptyContractAndCallIt_1wei:"
        "stCreateTest.CREATE_EmptyContractAndCallIt_0wei:"
        "stCreateTest.CreateCollisionToEmpty:"
        "stCreateTest.CREATE_EmptyContractWithStorageAndCallIt_1wei:"
        "stCreateTest.CREATE_ContractSuicideDuringInit_WithValueToItself:"
        "stCreateTest.CREATE_HighNonce:"
        "stCreateTest.TransactionCollisionToEmptyButNonce:"
        "stCreateTest.CREATE_FirstByte_loop:"
        "stCreateTest.CreateOOGafterMaxCodesize:"
        "stCreateTest.TransactionCollisionToEmptyButCode:"
        "stCreateTest.TransactionCollisionToEmpty:"
        "stCreateTest.CREATE_EOF1:"
        "stCreateTest.CREATE_AcreateB_BSuicide_BStore:"
        "stCreateTest.CREATE_ContractRETURNBigOffset:"
        "stCreateTest.createFailResult:"
        "stCreateTest.CreateCollisionResults:"
        "stCreateTest.createLargeResult:"
        "stCreateTest.CodeInConstructor:"
        "stCreateTest.CreateResults:"
        "stExample.solidityExample:"
        "stMemoryTest.memCopySelf:"
        "VMTests/vmPerformance.*:"
        /**/
        ;

    // constexpr auto single_test = "stCreateTest.CreateOOGafterInitCode:"sv;
    constexpr auto single_test = ""sv;

    std::string filter = "--gtest_filter=";
    const auto argv_end = argv + argc;
    if (const auto filter_arg = std::find(argv, argv_end, "--gtest_filter=builtin"sv);
        filter_arg != argv_end)
    {
        filter += (single_test.empty() ? known_passing_tests : single_test.data());
        *filter_arg = filter.data();
    }

    testing::InitGoogleTest(&argc, argv);

    if (argc != 2)
        return -1;

    const fs::path root_test_dir{argv[1]};
    for (const auto& dir_entry : fs::recursive_directory_iterator{root_test_dir})
    {
        const auto& p = dir_entry.path();
        if (dir_entry.is_regular_file() && p.extension() == ".json")
        {
            const auto d = fs::relative(p, root_test_dir);
            testing::RegisterTest(d.parent_path().c_str(), d.stem().c_str(), nullptr, nullptr,
                p.c_str(), 0, [p]() -> testing::Test* { return new StateTest(p); });
        }
    }

    return RUN_ALL_TESTS();
}
