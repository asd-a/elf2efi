/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#include <cctype>
#include <charconv>
#include <config.hpp>
#include <cstddef>
#include <cstring>
#include <elf2efi.hpp>
#include <fcntl.h>
#include <format>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
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
        char short_name;
        const char *long_name;
        const char *description;
        const char *addons;
        inline bool check(const char *argv) const {
            if (short_name != 0 && argv[0] == '-' && argv[1] == short_name && argv[2] == '\0')
                return true;
            return argv[0] == '-' && argv[1] == '-' && std::strcmp(long_name, argv + 2) == 0;
        }
        std::function<std::optional<std::string>()> formatter;
        inline void format() const {
            if (auto _ = formatter()) {
                err(ERR_CMD, "Invalid {}: {}.", long_name, *_);
            }
        }
    };
    std::vector<ArgOption> opts;

    inline void print_help(std::ostream &out) const {
        out << std::format(
            "Usage: {} [OPTIONS] {}\n\v"
            "Description:\n{}\n\v"
            "Options:\n",
            name,
            addons,
            description);
        for (const auto &opt : opts) {
            std::string _ = "    ";
            if (opt.short_name != 0) {
                _ = std::format("-{}, ", opt.short_name);
            }
            _ = std::format("  {}--{} {}", _, opt.long_name, opt.addons);
            if (_.size() > 20)
                out << std::format("{}\n{:<30}\t{}\n", _, "", opt.description);
            else
                out << std::format("{:<30}\t{}\n", _, opt.description);
        }
        out.flush();
    }
    inline auto &find(const char *argv) const {
        for (const auto &opt : opts)
            if (opt.check(argv)) return opt;
        err(ERR_CMD, "Unknown argument: {}", argv);
    }
};
#define OPTSTR std::optional<std::string>
#define NULLOPT OPTSTR(std::nullopt)

template <const int base = 0>
static inline bool format_int(const char *first, const char *last, auto &value) {
    auto [ptr, ec] = std::from_chars(first, last, value, base);
    return (ptr != last || ec != std::errc{});
}

template <const int base = 0>
static inline bool format_int(const std::string &str, auto &value) {
    auto first = str.c_str(), last = str.c_str() + str.size();
    auto [ptr, ec] = std::from_chars(first, last, value, base);
    return (ptr != last || ec != std::errc{});
}

static inline config parse_args(int argc, char *const argv[]) {
    config cfg{
        // default settings
        .inFile{},
        .outFile{},
        .subsystem = 0,
        .subsystemMajor = 0,
        .subsystemMinor = 0,
        .stackReserve = 0x100000,
        .stackCommit = 0x1000,
        .heapReserve = 0x100000,
        .heapCommit = 0x1000,
    };
    auto ind = 1;
    using std::string, std::vector;
    vector<string> others;
    ArgOptions arg_opts{
        "elf2efi",
        "<IN_ELF> <OUT_EFI>",
        "A tool to convert static-PIE ELF file to EFI image.",
    };
    arg_opts.opts = {
        {
            'h',
            "help",
            "Print this help message",
            "",
            [&]() -> OPTSTR {
                arg_opts.print_help(std::cout);
                exit(0);
            },
        },
        {
            'v',
            "version",
            "Print the version info",
            "",
            [&]() -> OPTSTR {
                print("{} {}", arg_opts.name, version);
                exit(0);
            },
        },
        {
            0,
            "subsystem",
            "Specify the image subsystem (and version)",
            "<SUBSYSTEM_ID>[:<MAJOR>.<MINOR>]",
            [&]() -> OPTSTR {
                if (auto ptr = std::strchr(argv[++ind], ':')) {
                    auto _ = std::strchr(ptr, '.');
                    return _ == nullptr || format_int(argv[ind], ptr, cfg.subsystem) ||
                                   format_int<10>(ptr + 1, _, cfg.subsystemMajor) ||
                                   format_int<10>(_ + 1, cfg.subsystemMinor)
                               ? argv[ind]
                               : NULLOPT;
                } else {
                    return format_int(argv[ind], cfg.subsystem) ? argv[ind] : NULLOPT;
                }
            },
        },
        {
            0,
            "stack",
            "Specify the stack reserve and commit size",
            "<RESERVE_SIZE>[,<COMMIT_SIZE>]",
            [&]() -> OPTSTR {
                if (auto ptr = std::strchr(argv[++ind], ',')) {
                    return format_int(argv[ind], ptr, cfg.stackReserve) ||
                                   format_int(ptr + 1, cfg.stackCommit)
                               ? argv[ind]
                               : NULLOPT;
                } else {
                    return format_int(argv[ind], cfg.stackReserve) ? argv[ind] : NULLOPT;
                }
            },
        },
        {
            0,
            "heap",
            "Specify the heap reserve and commit size",
            "<RESERVE_SIZE>[,<COMMIT_SIZE>]",
            [&]() -> OPTSTR {
                if (auto ptr = std::strchr(argv[++ind], ',')) {
                    return format_int(argv[ind], ptr, cfg.heapReserve) ||
                                   format_int(ptr + 1, cfg.heapCommit)
                               ? argv[ind]
                               : NULLOPT;
                } else {
                    return format_int(argv[ind], cfg.heapReserve) ? argv[ind] : NULLOPT;
                }
            },
        },
    };
    for (; ind < argc; ++ind) {
        if (argv[ind][0] == '-') {
            // options
            arg_opts.find(argv[ind]).format();
        } else {
            // others
            others.emplace_back(argv[ind]);
        }
    }
    if (others.size() > 2) {
        err(ERR_CMD, "Too many arguments.");
    }
    if (others.size() < 2) {
        err(ERR_CMD, "Too few arguments.");
    }
    cfg.inFile = others.front();
    cfg.outFile = others.back();
    return cfg;
}

int main(int argc, char *const argv[]) {
    auto cfg = parse_args(argc, argv);
    struct stat state;
    int fd = open(cfg.inFile.c_str(), O_RDONLY);
    if (fd == -1) {
        err(ERR_SYS, "Failed to open ELF file \"{}\".", cfg.inFile);
    }
    if (fstat(fd, &state) == -1) {
        err(ERR_SYS, "Failed to open ELF file \"{}\".", cfg.inFile);
    }
    auto raw = mmap(nullptr, state.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (raw == MAP_FAILED) {
        err(ERR_SYS, "Failed to open ELF file \"{}\".", cfg.inFile);
    }
    auto data = DataIter(raw);
    const char *e_ident = data;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        err(ERR_INPUT, "Invalid ELF file.");
    }
    if (e_ident[EI_CLASS] != ELFCLASS32 && e_ident[EI_CLASS] != ELFCLASS64) {
        err(ERR_INPUT, "Invalid ELF class: {}", e_ident[EI_CLASS]);
    }
    e_ident[EI_CLASS] == ELFCLASS32 ? elf2efi32(cfg, std::move(data))
                                    : elf2efi64(cfg, std::move(data));
    close(fd);
    return 0;
}