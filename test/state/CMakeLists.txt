# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_library(evmone-state STATIC)
add_library(evmone::state ALIAS evmone-state)
target_link_libraries(evmone-state PRIVATE evmone)
target_include_directories(evmone-state PRIVATE ${evmone_private_include_dir})
target_sources(
    evmone-state PRIVATE
    account.hpp
    precompiles.hpp
    precompiles.cpp
    rlp.hpp
    state.hpp
    state.cpp
    trie.hpp
    utils.hpp
)
