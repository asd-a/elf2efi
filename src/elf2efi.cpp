/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#include <elf2efi.hpp>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

const char *version = "1.0.0";

int main(int argc, char *const argv[]) {
    auto cfg = parse_args(argc, argv);
    struct stat state;
    int fd = open(cfg.in.c_str(), O_RDONLY);
    if (fd == -1) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.in);
    }
    if (fstat(fd, &state) == -1) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.in);
    }
    auto raw = mmap(NULL, state.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (raw == MAP_FAILED) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.in);
    }
    auto data = DataIter(raw);
    const char *e_ident = data;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        err(1, "Invalid ELF file.\n");
    }
    if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
        err(1, "Invalid ELF class ({}).\n", e_ident[EI_CLASS]);
    }
    e_ident[EI_CLASS] == ELFCLASS32 ? elf2efi32(cfg, std::move(data))
                                    : elf2efi64(cfg, std::move(data));
    close(fd);
    return 0;
}