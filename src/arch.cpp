/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#include <config.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
static void elf2efi(const config &cfg, DataIter &&data);
#if ARCH_CLASS == 32
#include <arch32.h>
void elf2efi32(const config &cfg, DataIter &&data) { return elf2efi(cfg, std::move(data)); }
#elif ARCH_CLASS == 64
#include <arch64.h>
void elf2efi64(const config &cfg, DataIter &&data) { return elf2efi(cfg, std::move(data)); }
#else
#error "Unsupported processor class."
#endif
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static inline std::uint16_t pe_machine(Elf_Half e_machine) {
    switch (e_machine) {
        case EM_386:
            return IMAGE_FILE_MACHINE_I386;
        case EM_IA_64:
            return IMAGE_FILE_MACHINE_IA64;
        case EM_X86_64:
            return IMAGE_FILE_MACHINE_X64;
        case EM_ARM:
            return IMAGE_FILE_MACHINE_ARMTHUMB_MIXED;
        case EM_LOONGARCH:
            return IMAGE_FILE_MACHINE_LOONGARCH;
        case EM_RISCV:
            return IMAGE_FILE_MACHINE_RISCV;
        default:
            err(ERR_UNSUP, "Unsupport machine type ({}).", e_machine);
    }
}

template <typename T>
static inline std::vector<T *>
table_with_num(const DataIter &data, auto offset, auto entsize, auto num) {
    std::vector<T *> _(num);
    for (auto base = data + offset; auto &x : _) {
        x = base;
        base += entsize;
    }
    return _;
}
static inline std::vector<Elf_Addr>
relocation_table(const DataIter &data, auto offset, auto base) {
    std::vector<Elf_Addr> res, relr, relrsz, relrent;
    bool _is_pie = false;
    for (const Elf_Dyn *dyn = data + offset; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_REL:
            case DT_RELA:
            case DT_RELSZ:
            case DT_RELASZ:
            case DT_RELENT:
            case DT_RELAENT:
                err(ERR_UNSUP,
                    "Unsupport relocation type {}, (use link arg `-z pack-relative-relocs` "
                    "instead).",
                    dyn->d_tag);
            case DT_RELR:
                relr.push_back(dyn->d_un.d_ptr);
                break;
            case DT_RELRSZ:
                relrsz.push_back(dyn->d_un.d_val);
                break;
            case DT_RELRENT:
                relrent.push_back(dyn->d_un.d_val);
                break;
            case DT_FLAGS_1:
                if (!(dyn->d_un.d_val & DF_1_PIE)) {
                    err(ERR_UNSUP, "ELF file is not Position-Independent-Executable.");
                }
                _is_pie = true;
            default:
                break;
        }
    }
    if (!_is_pie) {
        err(ERR_UNSUP, "ELF file is not Position-Independent-Executable.");
    }
    if (relr.size() != relrsz.size() || relr.size() != relrent.size()) {
        err(ERR_INPUT,
            "The number of ELF DT_RELR({}), DT_RELRSZ({}), DT_RELRENT({}) not match.",
            relr.size(),
            relrsz.size(),
            relrent.size());
    }
    for (auto _start = relr.begin(),
              _end = relr.end(),
              _sz = relrsz.begin(),
              _entsz = relrent.begin();
         _start != _end;
         ++_start, ++_sz, ++_entsz) {
        auto entries = table_with_num<Elf_Relr>(data, *_start, *_entsz, *_sz / *_entsz);
        for (Elf_Addr next = 0; auto entry : entries) {
            if (*entry & 1) {
                if (next == 0) {
                    err(ERR_INPUT, "Invalid ELF relative relocation.");
                }
                for (int i = 1; i < ARCH_CLASS; ++i, next += sizeof(Elf_Addr)) {
                    if ((*entry >> i) & 1) {
                        *(Elf_Addr *)(data + next) += base;
                        res.push_back(next);
                    }
                }
            } else {
                res.push_back(next = *entry);
                *(Elf_Addr *)(data + next) += base;
                next += sizeof(Elf_Addr);
            }
        }
    }
    return res;
}
#define RELOCATION_ENTRY(x, y) (((x) << 12) | ((y) & 0xfff))
#define TOCHARS(x) (reinterpret_cast<const char *>(x))
struct PeRelocationBlock {
    EFI_IMAGE_BASE_RELOCATION header;
    std::vector<std::uint16_t> entries;
    explicit PeRelocationBlock(std::uint32_t rva) : header{.VirtualAddress = rva}, entries() {}
    inline void update() {
        header.SizeOfBlock =
            ALIGN_TO(sizeof(EFI_IMAGE_BASE_RELOCATION) + entries.size() * 2, 4);
    }
};

static void elf2efi(const config &cfg, DataIter &&data) {
#if ARCH_CLASS == 32
    if(cfg.base >> 32){
        err(ERR_CMD, "Image base:{:x} is too large.", cfg.base);
    }
#endif
    using std::vector, std::string, std::pair, std::ios, std::uint32_t, std::uint16_t;
    namespace stdfs = std::filesystem;
    Elf_Ehdr *ehdr = data;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) { // never
        err(ERR_INPUT, "Invalid ELF file.");
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS) { // never
        err(ERR_INPUT, "ELF class is not {}.", ARCH_CLASS);
    }

    // check e_shoff
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        err(ERR_UNSUP, "ELF file has no section header table.");
    }

    // check e_phoff
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) {
        err(ERR_UNSUP, "ELF file has no program header table.");
    }

    // check data encoding
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        err(ERR_UNSUP, "ELF data encoding is not little-endian.");
    }
    // check e_type
    if (ehdr->e_type != ET_DYN) {
        err(ERR_UNSUP, "ELF type:{} is not Position-Independent-Executable.", ehdr->e_type);
    }

    auto phtable(
        table_with_num<Elf_Phdr>(data, ehdr->e_phoff, ehdr->e_phentsize, ehdr->e_phnum));
    auto shtable(
        table_with_num<Elf_Shdr>(data, ehdr->e_shoff, ehdr->e_shentsize, ehdr->e_shnum));

    // const char *shstrtable = data + shtable.at(ehdr->e_shstrndx)->sh_offset;

    vector<Elf_Phdr *> load_phdrs;

    // load PT_LOAD into pe sections
    for (auto phdr : phtable) {
        if (phdr->p_type == PT_INTERP) {
            err(ERR_UNSUP, "ELF file is not static linked.");
        }
        if (phdr->p_type != PT_LOAD) continue;
        if (phdr->p_align != SECTION_ALIGNMENT) {
            err(ERR_UNSUP, "ELF segment PT_LOAD is not properly aligned ({}).", phdr->p_align);
        }
        load_phdrs.push_back(phdr);
    }
    if (load_phdrs.empty()) {
        err(ERR_UNSUP, "ELF file has no segment load into mem.");
    }

    // PE relro feature
    for (auto relro_phdr : phtable) {
        if (relro_phdr->p_type != PT_GNU_RELRO) continue;
        for (auto phdr : load_phdrs)
            if (relro_phdr->p_vaddr <= phdr->p_vaddr &&
                phdr->p_vaddr + phdr->p_memsz <= relro_phdr->p_vaddr + relro_phdr->p_memsz)
                phdr->p_flags = PF_R;
    }

    /// todo: copy sections
    // for (auto shdr : shtable) {
    // }

    uint32_t size_of_headers = ALIGN_TO(
        sizeof(EFI_IMAGE_DOS_HEADER) + sizeof(EFI_IMAGE_NT_HEADER) +
            sizeof(EFI_IMAGE_SECTION_HEADER) * (load_phdrs.size() + 1) // add reloc section
        ,
        FILE_ALIGNMENT);
    Elf_Off segment_offset = ALIGN_TO(size_of_headers, SECTION_ALIGNMENT) -
                             ALIGN_DOWN(load_phdrs.front()->p_vaddr, SECTION_ALIGNMENT);

    vector<Elf_Addr> relocs;
    bool has_dynamic = false;
    for (auto phdr : phtable) {
        if (phdr->p_type != PT_DYNAMIC) continue;
        has_dynamic = true;
        auto _ = relocation_table(data, phdr->p_offset, cfg.base + segment_offset);
        relocs.insert(relocs.end(), _.begin(), _.end());
    }
    if (!has_dynamic) {
        err(ERR_UNSUP, "ELF file has no dynamic segment.");
    }
    std::ofstream pe(cfg.outFile, ios::binary | ios::out);
    if (!pe) {
        err(ERR_SYS, "Failed to open PE file.");
    }

    vector<EFI_IMAGE_SECTION_HEADER> sections;
    uint32_t section_offset = size_of_headers,
             lastvma = ALIGN_TO(size_of_headers, SECTION_ALIGNMENT), size_of_code = 0,
             size_of_data = 0, base_of_code = 0, base_of_data = 0;
    EFI_IMAGE_DATA_DIRECTORY RelocDict{};
    for (auto phdr : load_phdrs) {
        auto n_vaddr = ALIGN_DOWN(phdr->p_vaddr, SECTION_ALIGNMENT);
        if (lastvma > n_vaddr + segment_offset) {
            err(ERR_UNSUP | ERR_INPUT, // occurs mostly the elf file invalid
                "ELF PT_LOAD segments overlaps ({:x} overlaps the next {:x}).",
                lastvma,
                n_vaddr + segment_offset);
        }
        if (phdr->p_filesz != 0 && !pe.seekp(section_offset + phdr->p_vaddr - n_vaddr, ios::beg)
                                        .write(data + phdr->p_offset, phdr->p_filesz)) {
            err(ERR_SYS, "Failed to write to PE section at {:x}.", section_offset);
        }
        uint32_t n_size =
            phdr->p_filesz == 0
                ? 0
                : ALIGN_TO(phdr->p_filesz + phdr->p_vaddr - n_vaddr, FILE_ALIGNMENT);
        EFI_IMAGE_SECTION_HEADER section = {
            .Misc{.VirtualSize =
                      static_cast<uint32_t>(phdr->p_memsz + phdr->p_vaddr - n_vaddr)},
            .VirtualAddress = static_cast<uint32_t>(n_vaddr + segment_offset),
            .SizeOfRawData = n_size,
            .PointerToRawData = section_offset,
        };
        switch (phdr->p_flags) {
            case PF_X | PF_R:
                section.Characteristics = PE_CHARACTERISTICS_RX;
                memcpy(section.Name, ".text\0\0\0", 8);
                size_of_code += section.Misc.VirtualSize;
                if (!base_of_code) base_of_code = section.VirtualAddress;
                break;
            case PF_R:
                section.Characteristics = PE_CHARACTERISTICS_R;
                memcpy(section.Name, ".rodata\0", 8);
                size_of_data += section.Misc.VirtualSize;
                if (!base_of_data) base_of_data = section.VirtualAddress;
                break;
            case PF_R | PF_W:
                section.Characteristics = PE_CHARACTERISTICS_RW;
                memcpy(section.Name, ".data\0\0\0", 8);
                size_of_data += section.Misc.VirtualSize;
                if (!base_of_data) base_of_data = section.VirtualAddress;
                break;
            default:
                err(ERR_UNSUP, "Unsupport program segment flags ({:x}).", phdr->p_flags);
        }
        lastvma = ALIGN_TO(phdr->p_vaddr + phdr->p_memsz + segment_offset, SECTION_ALIGNMENT);
        section_offset += n_size;
        sections.emplace_back(std::move(section));
    }

    /// todo: copy sections
    // for (auto shdr : copy_shdrs) {
    // }

    if (!relocs.empty()) {
        // generate reloc secton
        std::sort(relocs.begin(), relocs.end());
        auto start = section_offset = ALIGN_TO(section_offset, 4);
        vector<PeRelocationBlock> blocks;
        for (auto reloc : relocs) {
            uint32_t rva = (reloc + segment_offset) & ~((Elf_Addr)0xfff);
            if (blocks.empty() || rva != blocks.back().header.VirtualAddress) {
                blocks.emplace_back(rva);
            }
            blocks.back().entries.push_back(
                RELOCATION_ENTRY(IMAGE_REL_BASED_TYPE, reloc + segment_offset));
        }
        for (auto &block : blocks) {
            block.update();
            if (!pe.seekp(section_offset, ios::beg)
                     .write(TOCHARS(&block.header), sizeof(EFI_IMAGE_BASE_RELOCATION))
                     .write(TOCHARS(block.entries.data()), block.entries.size() * 2)) {
                err(ERR_SYS, "Failed to write to PE .reloc section at {:x}.", section_offset);
            }
            section_offset += block.header.SizeOfBlock;
        }

        EFI_IMAGE_SECTION_HEADER section = {
            .Name = ".reloc",
            .Misc{.VirtualSize = RelocDict.Size = section_offset - start},
            .VirtualAddress = RelocDict.VirtualAddress = lastvma,
            .SizeOfRawData = ALIGN_TO(section_offset - start, FILE_ALIGNMENT),
            .PointerToRawData = start,
            .Characteristics = PE_CHARACTERISTICS_DISCARD,
        };
        size_of_data += section.Misc.VirtualSize;
        lastvma = ALIGN_TO(lastvma + section.Misc.VirtualSize, SECTION_ALIGNMENT);
        section_offset = ALIGN_TO(section_offset, FILE_ALIGNMENT);
        sections.emplace_back(std::move(section));
    }

    log("PE file total size {} of bytes", section_offset);

    EFI_IMAGE_DOS_HEADER doshdr = {
        .e_magic = EFI_IMAGE_DOS_SIGNATURE,
        .e_lfanew = sizeof(EFI_IMAGE_DOS_HEADER),
    };
    EFI_IMAGE_NT_HEADER nthdr = {
        .Signature = EFI_IMAGE_NT_SIGNATURE,
        .FileHeader{
            .Machine = pe_machine(ehdr->e_machine),
            .NumberOfSections = static_cast<uint16_t>(sections.size()),
            .TimeDateStamp = static_cast<uint32_t>(time(nullptr)),
            .SizeOfOptionalHeader = sizeof(EFI_IMAGE_OPTIONAL_HEADER),
            .Characteristics = IMAGE_FILE_CHARACTERISTICS,
        },
        .OptionalHeader{
            .Magic = EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC,
            .SizeOfCode = size_of_code,
            .SizeOfInitializedData = size_of_data,
            .AddressOfEntryPoint = static_cast<uint32_t>(ehdr->e_entry + segment_offset),
            .BaseOfCode = base_of_code,
#if ARCH_CLASS == 32
            .BaseOfData = base_of_data,
            .ImageBase = static_cast<uint32_t>(cfg.base),
#else
            .ImageBase = cfg.base,
#endif
            .SectionAlignment = SECTION_ALIGNMENT,
            .FileAlignment = FILE_ALIGNMENT,
            .MajorSubsystemVersion = cfg.subsystemMajor,
            .MinorSubsystemVersion = cfg.subsystemMinor,
            .SizeOfImage = lastvma,
            .SizeOfHeaders = size_of_headers,
            .Subsystem = cfg.subsystem,
            .DllCharacteristics = IMAGE_DLLCHARACTERISTICS,
            .SizeOfStackReserve = cfg.stackReserve,
            .SizeOfStackCommit = cfg.stackCommit,
            .SizeOfHeapReserve = cfg.heapReserve,
            .SizeOfHeapCommit = cfg.heapCommit,
            .NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES,
        },
    };
    nthdr.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC] = RelocDict;
    if (!pe.seekp(0, ios::beg)
             .write(TOCHARS(&doshdr), sizeof(EFI_IMAGE_DOS_HEADER))
             .write(TOCHARS(&nthdr), sizeof(EFI_IMAGE_NT_HEADER))
             .write(TOCHARS(sections.data()),
                    sizeof(EFI_IMAGE_SECTION_HEADER) * sections.size())) {
        err(ERR_SYS, "Failed to write to PE headers.");
    }
    try {
        stdfs::resize_file(cfg.outFile, section_offset);
    } catch (stdfs::filesystem_error &ec) {
        err(ERR_SYS, "Failed to resize PE file to alignment: {}", ec.what());
    }
    log("Finished.");
}