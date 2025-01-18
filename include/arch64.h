/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <elf-local.h>
#include <pe.h>

#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_INFO ELF64_R_INFO
#define ELFCLASS ELFCLASS64
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Chdr Elf_Chdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Nhdr Elf_Nhdr;
typedef Elf64_Move Elf_Move;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Syminfo Elf_Syminfo;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Relr Elf_Relr;
typedef Elf64_Half Elf_Half;
typedef Elf64_Word Elf_Word;
typedef Elf64_Sword Elf_Sword;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_Sxword Elf_Sxword;
typedef Elf64_Off Elf_Off;
typedef Elf64_Section Elf_Section;
typedef Elf64_Versym Elf_Versym;

#define IMAGE_BASE 0x00400000
#define IMAGE_DLLCHARACTERISTICS                                                               \
    (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |        \
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
#define IMAGE_FILE_MACHINE_RISCV IMAGE_FILE_MACHINE_RISCV64
#define IMAGE_FILE_MACHINE_LOONGARCH IMAGE_FILE_MACHINE_LOONGARCH64
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_FILE_CHARACTERISTICS                                                             \
    (EFI_IMAGE_FILE_EXECUTABLE_IMAGE | EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE |                    \
     EFI_IMAGE_FILE_DEBUG_STRIPPED)
typedef EFI_IMAGE_NT_HEADERS64 EFI_IMAGE_NT_HEADER;
typedef EFI_IMAGE_OPTIONAL_HEADER64 EFI_IMAGE_OPTIONAL_HEADER;

#define IMAGE_REL_BASED_TYPE EFI_IMAGE_REL_BASED_DIR64
