#
# Copyright (c) 2025, Asdro Huang. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#

override CC:=clang
override LD:=clang
override CXX:=clang -xc++
override CXXFLAGS:=-std=c++20  -Iinclude -O3 -Werror -Wall -EL -stdlib=libc++
override LDFLAGS:=-fuse-ld=lld -O3 -Wl,-EL -Werror -Wall -lc++
override HEADERS:= $(wildcard include/*.h) $(wildcard include/*.hpp)

BUILDDIR := build


ifndef ROOTDIR
	ROOTDIR := $(CURDIR)
endif

.PHONY: all clean

OBJ:=parse.o elf2efi.o

OBJ:=$(foreach var,$(OBJ),$(BUILDDIR)/$(var))

all: $(BUILDDIR)/elf2efi

test:
	echo $(ROOTDIR)

$(BUILDDIR)/arch32.o:src/arch.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) -DARCH_CLASS=32 $< -o $@

$(BUILDDIR)/arch64.o:src/arch.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) -DARCH_CLASS=64 $< -o $@

$(OBJ):$(BUILDDIR)/%.o:src/%.cpp $(HEADERS)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BUILDDIR)/elf2efi: $(OBJ) $(BUILDDIR)/arch32.o $(BUILDDIR)/arch64.o
	$(LD) $(LDFLAGS) $^ -o $@

clean:
	rm -r $(BUILDDIR)