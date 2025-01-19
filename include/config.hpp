/**
Copyright (c) 2025, Asdro Huang. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#include <cstddef>
#include <cstdint>
#include <elf-local.h>
#include <pe.h>
#include <string>

#if __clang__ != 1
#error "Unsupport compiler"
#endif

#if __LITTLE_ENDIAN__ != 1 || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Not little endian"
#endif

#if !defined(RELEASE)
[[noreturn]]
#else
[[deprecated("Uncompleted todo in RELEASE version")]]
#endif
static inline void todo() {
    std::exit(2);
}

static_assert(sizeof(std::int8_t) == 1, "sizeof(std::int8_t) != 1");
static_assert(sizeof(std::uint8_t) == 1, "sizeof(std::uint8_t) != 1");
static_assert(alignof(std::int8_t) == 1, "alignof(std::int8_t) != 1");
static_assert(alignof(std::uint8_t) == 1, "alignof(std::uint8_t) != 1");
static_assert(sizeof(std::int16_t) == 2, "sizeof(std::int16_t) != 2");
static_assert(sizeof(std::uint16_t) == 2, "sizeof(std::uint16_t) != 2");
static_assert(alignof(std::int16_t) == 2, "alignof(std::int16_t) != 2");
static_assert(alignof(std::uint16_t) == 2, "alignof(std::uint16_t) != 2");
static_assert(sizeof(std::int32_t) == 4, "sizeof(std::int32_t) != 4");
static_assert(sizeof(std::uint32_t) == 4, "sizeof(std::uint32_t) != 4");
static_assert(alignof(std::int32_t) == 4, "alignof(std::int32_t) != 4");
static_assert(alignof(std::uint32_t) == 4, "alignof(std::uint32_t) != 4");
static_assert(sizeof(std::int64_t) == 8, "sizeof(std::int64_t) != 8");
static_assert(sizeof(std::uint64_t) == 8, "sizeof(std::uint64_t) != 8");
static_assert(alignof(std::int64_t) == 8, "alignof(std::int64_t) != 8");
static_assert(alignof(std::uint64_t) == 8, "alignof(std::uint64_t) != 8");

struct config {
    std::string inFile, outFile; //, copy;
    std::uint16_t subsystem;
};
#define SECTION_ALIGNMENT 0x1000 // 4096
#define FILE_ALIGNMENT 0x0200    // 512

#define PE_CHARACTERISTICS_RX                                                                  \
    (EFI_IMAGE_SCN_MEM_EXECUTE | EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_CNT_CODE)
#define PE_CHARACTERISTICS_RW                                                                  \
    (EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_CNT_INITIALIZED_DATA)
#define PE_CHARACTERISTICS_R (EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_CNT_INITIALIZED_DATA)

#define PE_CHARACTERISTICS_DISCARD                                                             \
    (EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_CNT_INITIALIZED_DATA |                             \
     EFI_IMAGE_SCN_MEM_DISCARDABLE)

#define ALIGN_TO(x, y) (((x) + ((y) - 1)) & (~((y) - 1)))

#define ALIGN_DOWN(x, y) ((x) & (~((y) - 1)))

#define ERR_CMD 1   // command line error
#define ERR_SYS 2   // system error
#define ERR_INPUT 4 // invalid elf file input
#define ERR_UNSUP 8 // unsupported

#include <format>
#include <iostream>
#include <string>

template <typename... Args>
static inline void log(std::format_string<Args...> fmt, Args &&...args) {
    std::clog <<"LOG: "<< std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
}

template <typename... Args>
[[noreturn]] static inline void
err(auto exit_code, std::format_string<Args...> fmt, Args &&...args) {
    std::cerr <<"ERROR: " <<std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
    exit(exit_code);
}

template <typename... Args>
static inline void print(std::format_string<Args...> fmt, Args &&...args) {
    std::cout << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
}

using std::exit;

struct DataIter {
  private:
    void *raw;

  public:
    explicit DataIter(void *raw) : raw(raw) {}
    inline DataIter &operator+=(const auto &x) {
        raw = (char *)raw + x;
        return *this;
    }
    inline DataIter &operator-=(const auto &x) {
        raw = (char *)raw - x;
        return *this;
    }
    inline DataIter operator+(const auto &x) const { return DataIter((char *)raw + x); }
    inline DataIter operator-(const auto &x) const { return DataIter((char *)raw - x); }
    template <typename T>
    inline operator T *() const {
        return reinterpret_cast<T *>(raw);
    }
    template <typename T>
    inline operator const T *() const {
        return reinterpret_cast<const T *>(raw);
    }
};