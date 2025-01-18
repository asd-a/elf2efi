/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#include <config.hpp>
extern const char *version;
extern void elf2efi32(const config &cfg, DataIter&& data);
extern void elf2efi64(const config &cfg, DataIter&& data);