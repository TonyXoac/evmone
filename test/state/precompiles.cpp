// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include <cassert>

namespace evmone::state
{
evmc::result call_precompiled(evmc_revision rev, const evmc_message& msg) noexcept
{
    auto gas = msg.gas;
    (void)rev;
    const auto id = msg.code_address.bytes[19];
    switch (id)
    {
    case 0x04:
    {
        const auto cost = static_cast<int64_t>(15 + 3 * ((msg.input_size + 31) / 32));
        gas -= cost;
        if (gas < 0)
            return evmc::result{EVMC_OUT_OF_GAS, 0, nullptr, 0};
        return evmc::result{EVMC_SUCCESS, gas, msg.input_data, msg.input_size};
    }
    default:
        assert(false && "precompiles not implemented");
    }
}
}  // namespace evmone::state
