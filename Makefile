#
# Copyright (c) 2025, Asdro Huang. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
#

LD:=clang++
CXX:=clang++
LDFLAGS:=-O3 -Werror -Wall -EL -Wl,-EL
CXXFLAGS:=-std=c++20 -Iinclude -O3 -Werror -Wall -EL

HEADERS:= $(wildcard include/*.h) $(wildcard include/*.hpp)
BUILDDIR:= build

.PHONY: all clean

all: $(BUILDDIR)/elf2efi

$(BUILDDIR)/arch32.o:src/arch.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -DARCH_CLASS=32 $< -o $@

$(BUILDDIR)/arch64.o:src/arch.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) -DARCH_CLASS=64 $< -o $@

$(BUILDDIR)/elf2efi:$(BUILDDIR)/elf2efi.o $(BUILDDIR)/arch32.o $(BUILDDIR)/arch64.o
	@mkdir -p $(dir $@)
	$(LD) $(LDFLAGS) $^ -o $@

$(BUILDDIR)/%.o:src/%.cpp $(HEADERS)
	@mkdir -p $(dir $@)
	$(CXX) -c $(CXXFLAGS) $< -o $@

clean:
	@rm -f $(BUILDDIR)/*