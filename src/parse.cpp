/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#include <config.hpp>
#include <elf2efi.hpp>
#include <getopt.h>

static const struct option longopts[] = {{"version", 0, NULL, 'v'},
                                         {"help", 0, NULL, 'h'},
                                         {"subsystem", 1, NULL, 2},
                                         {"version-major", 1, NULL, 3},
                                         {"version-minor", 1, NULL, 4},
                                         {"efi-major", 1, NULL, 5},
                                         {"efi-minor", 1, NULL, 6},
                                         //  {"minimum-sections", 1, NULL, 7},
                                         //  {"copy-sections", 1, NULL, 8},
                                         {"in", 1, NULL, 'i'},
                                         {"out", 1, NULL, 'o'},
                                         {}};
static const char *shortopts = "hvi:o:";
static inline void print_help(const char *name) {
    print(
        "\
OVERVIEW: Convert static-pie ELF binaries to PE/EFI\n\
USAGE: {} [OPTIONS]\n\
OPTIONS:\n\
    -i, --in <FILE>                 (required) Input ELF file\n\
    -o, --out <FILE>                (required) Output PE/EFI file\n\
        --subsystem <INT>           PE subsystem\n\
        --version-major <INT>       Major image version of EFI image\n\
        --version-minor <INT>       Minor image version of EFI image\n\
        --efi-major <INT>           Minimum major EFI subsystem version\n\
        --efi-minor <INT>           Minimum minor EFI subsystem version\n\
        --minimum-sections <INT>    Minimum number of sections to leave space for\n\
        --copy-sections <STR>       Copy these sections if found\n\
    -v, --version                   Print version\n\
    -h, --help                      Print this help message\n\
",
        name);
}

static inline void print_version(const char *name) { print("{} {}\n", name, version); }
config parse_args(int argc, char *const argv[]) {
    using std::exit, std::fprintf, std::strtoul;
    config cfg = {
        .in = "",
        .out = "",
        // .copy = "",
        .subsystem = 0,
        .version_major = 0,
        .version_minor = 0,
        .efi_major = 0,
        .efi_minor = 0,
        // .minimum_sections = 0,
    };
    for (char *end = NULL;;) {
        switch (getopt_long(argc, argv, shortopts, longopts, NULL)) {
            case 'h':
                print_help(argv[0]);
                exit(0);
            case 'v':
                print_version(argv[0]);
                exit(0);
            case 2:
                cfg.subsystem = strtoul(optarg, &end, 0);
                if (optarg == NULL || *end != '\0') {
                    log("Invalid subsystem \"{}\".\n", optarg);
                    goto err;
                }
                break;
            case 3:
                cfg.version_major = strtoul(optarg, &end, 0);
                if (optarg == NULL || *end != '\0') {
                    log("Invalid version-major \"{}\".\n", optarg);
                    goto err;
                }
                break;
            case 4:
                cfg.version_minor = strtoul(optarg, &end, 0);
                if (optarg == NULL || *end != '\0') {
                    log("Invalid version-minor \"{}\".\n", optarg);
                    goto err;
                }
                break;
            case 5:
                cfg.efi_major = strtoul(optarg, &end, 0);
                if (optarg == NULL || *end != '\0') {
                    log("Invalid efi-major \"{}\".\n", optarg);
                    goto err;
                }
                break;
            case 6:
                cfg.efi_minor = strtoul(optarg, &end, 0);
                if (optarg == NULL || *end != '\0') {
                    log("Invalid efi-minor \"{}\".\n", optarg);
                    goto err;
                }
                break;
            // case 7:
            //     cfg.minimum_sections = strtoul(optarg, &end, 0);
            //     if (optarg == NULL || *end != '\0') {
            //         log("Invalid minimum-sections \"{}\"\n", optarg);
            //         goto err;
            //     }
            //     break;
            // case 8:
            //     cfg.copy = optarg;
            //     break;
            case 'i':
                cfg.in = optarg;
                break;
            case 'o':
                cfg.out = optarg;
                break;
            case -1:
                if (optind != argc) {
                    log("Invalid arguments.\n");
                    goto err;
                }
                goto out;
            default:
            err:
                print_help(argv[0]);
                exit(1);
        }
    }
out:
    if (cfg.in == "" || cfg.out == "") {
        log("Infile and outfile is required.\n");
        print_help(argv[0]);
        exit(1);
    }
    return cfg;
}