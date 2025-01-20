/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <elf-local.h>
#include <pe.h>

#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_INFO ELF32_R_INFO
#define ELFCLASS ELFCLASS32
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Chdr Elf_Chdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Nhdr Elf_Nhdr;
typedef Elf32_Move Elf_Move;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Syminfo Elf_Syminfo;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Relr Elf_Relr;
typedef Elf32_Half Elf_Half;
typedef Elf32_Word Elf_Word;
typedef Elf32_Sword Elf_Sword;
typedef Elf32_Xword Elf_Xword;
typedef Elf32_Sxword Elf_Sxword;
typedef Elf32_Off Elf_Off;
typedef Elf32_Section Elf_Section;
typedef Elf32_Versym Elf_Versym;

#define IMAGE_DLLCHARACTERISTICS                                                               \
    (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
#define IMAGE_FILE_MACHINE_RISCV IMAGE_FILE_MACHINE_RISCV32
#define IMAGE_FILE_MACHINE_LOONGARCH IMAGE_FILE_MACHINE_LOONGARCH32
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGE_FILE_CHARACTERISTICS                                                             \
    (EFI_IMAGE_FILE_EXECUTABLE_IMAGE | EFI_IMAGE_FILE_32BIT_MACHINE |                          \
     EFI_IMAGE_FILE_LINE_NUMS_STRIPPED | EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED)
typedef EFI_IMAGE_NT_HEADERS32 EFI_IMAGE_NT_HEADER;
typedef EFI_IMAGE_OPTIONAL_HEADER32 EFI_IMAGE_OPTIONAL_HEADER;

#define IMAGE_REL_BASED_TYPE EFI_IMAGE_REL_BASED_HIGHLOW