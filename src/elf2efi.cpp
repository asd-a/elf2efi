/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#include <cctype>
#include <charconv>
#include <config.hpp>
#include <cstring>
#include <elf2efi.hpp>
#include <fcntl.h>
#include <format>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

const char *version = "1.0.1";

struct ArgOptions {
    const char *name;
    const char *addons;
    const char *description;

    struct ArgOption {
        int type;
        const char *name;
        const char *description;
        const char *addons;
        inline bool check(const char *argv) const {
            if (31 < type && type < 127 && std::isprint((char)type)) {
                if (argv[0] == '-' && argv[1] == type && argv[2] == '\0') {
                    return true;
                }
            }
            return argv[0] == '-' && argv[1] == '-' && std::strcmp(name, argv + 2) == 0;
        }
    } opts[];

    inline void print_help(std::ostream &out) const {
        out << std::format(
            "Usage: {} [OPTIONS] {}\n\n"
            "Description: {}\n\n"
            "Options:\n",
            name,
            addons,
            description);
        for (auto opt = opts; opt->type != 0; ++opt) {
            std::string _ = "    ";
            if (31 < opt->type && opt->type < 127 && std::isprint((char)opt->type)) {
                _ = std::format("-{}, ", (char)opt->type);
            }
            _ = std::format("  {}--{} {}", _, opt->name, opt->addons);
            out << std::format("{:<32} \t {}\n", _, opt->description);
        }
    }
    inline auto find(const char *argv) const {
        for (auto opt = opts;; ++opt) {
            if (opt->type == 0 || opt->check(argv)) {
                return opt;
            }
        }
    }
};
static const ArgOptions opts = {
    .name = "elf2efi",
    .addons = "<IN_ELF> <OUT_EFI>",
    .description = "A tool to convert static-PIE ELF file to EFI image.",
    .opts{{'h', "help", "Print this help message", ""},
          {'v', "version", "Print the version info", ""},
          {-1, "subsystem", "Specify the image subsystem", "<ID>"},
          {}},
};
static inline config parse_args(int argc, char *const argv[]) {
    auto format_integral = [](const char *str, auto &value, const char *name) {
        auto [ptr, ec] = std::from_chars(str, str + std::strlen(str), value, 0);
        if (*ptr != '\0' || ec != std::errc{}) {
            err(1, "Invalid {}:{}\n", name, str);
        }
    };
    config cfg{};
    using std::string, std::vector;
    vector<string> others;
    for (auto ind = 1; ind < argc; ++ind) {
        if (argv[ind][0] == '-') {
            // options
            switch (auto opt = opts.find(argv[ind]); opt->type) {
                case 'h':
                    opts.print_help(std::cout);
                    exit(0);
                case 'v':
                    print("{} {}\n", argv[0], version);
                    exit(0);
                case -1: {
                    format_integral(argv[++ind], cfg.subsystem, opt->name);
                    break;
                }
                default:
                    log("Unknown argument: {}\n", argv[ind]);
                    opts.print_help(std::cerr);
                    exit(1);
            }
        } else {
            // others
            others.emplace_back(argv[ind]);
        }
    }
    if (others.size() > 2) {
        log("Too many arguments.\n");
        opts.print_help(std::cerr);
        exit(1);
    }
    if (others.size() < 2) {
        log("Too few arguments.\n");
        opts.print_help(std::cerr);
        exit(1);
    }
    cfg.infile = others.front();
    cfg.outfile = others.back();
    return cfg;
}

int main(int argc, char *const argv[]) {
    auto cfg = parse_args(argc, argv);
    struct stat state;
    int fd = open(cfg.infile.c_str(), O_RDONLY);
    if (fd == -1) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.infile);
    }
    if (fstat(fd, &state) == -1) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.infile);
    }
    auto raw = mmap(NULL, state.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (raw == MAP_FAILED) {
        err(1, "Failed to open ELF file \"{}\".\n", cfg.infile);
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