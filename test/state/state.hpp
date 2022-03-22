// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "account.hpp"

namespace evmone::state
{
class State
{
public:
    std::unordered_map<address, Account> accounts;
};
}  // namespace evmone::state
