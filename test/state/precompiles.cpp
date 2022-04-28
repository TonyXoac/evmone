// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "precompiles.hpp"
#include <cassert>

namespace evmone::state
{
evmc::result call_precompiled(evmc_revision rev, const evmc_message& msg) noexcept
{
    (void)rev;
    (void)msg;
    assert(false && "precompiles not implemented");
}
}  // namespace evmone::state
