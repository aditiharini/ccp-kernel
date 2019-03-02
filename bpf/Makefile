# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# Build bpf code (kernel) out-of-tree by referencing local copies of
# bpf .h files along with headers from kernel source tree.
# Creates similar environment to that used by samples/bpf by adding
# ../include/[bpf_endian.h,bpf_helpers.h,linux/types.h]. The latter is
# used to get definitions for u64, u32 etc which are needed by other kernel
# headers.
#
# - ../include/bpf_helpers.h is a copy of tools/testing/selftest/bpf/bpf_helpers.h
# - ../include/bpf_endian.h is a copy of tools/testing/selftest/bpf/bpf_endian.h
# - ../include/linux/types.h is a copy of tools/include/linux/types.h
#
#
# Assumptions:
#
# - kernel-uek-devel package or equivalent has installed (partial) source
#   tree in /usr/src/kernels/`uname -r`
#
# - llc/clang are available and support "bpf" target; check with "llc --verison"
#

OBJS = bpf_data_kern.o

LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -O2 -emit-llvm

# In case up-to-date headers are not installed locally in /usr/include,
# use source build.

linuxhdrs ?= /usr/src/linux-headers-4.19.0-041900

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include \

prefix ?= /usr/local

INSTALLPATH = $(prefix)/lib/bpf

install_PROGRAM = install
install_DIR = install -dv

export ARCH=x86

all: $(OBJS)

.PHONY: clean

clean:
	rm -f $(OBJS)

INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`

$(OBJS):  %.o:%.c
	$(CLANG) $(INC_FLAGS) \
			-D__KERNEL__ -D__ASM_SYSREG_H \
			-Wno-unused-value -Wno-pointer-sign \
			-Wno-compare-distinct-pointer-types \
			-Wno-gnu-variable-sized-type-not-at-end \
			-Wno-address-of-packed-member -Wno-tautological-compare \
			-Wno-unknown-warning-option \
			$(LINUXINCLUDE) \
			$(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

install: $(OBJS)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_PROGRAM) $^ -t $(INSTALLPATH)

uninstall: $(OBJS)
	rm -rf $(INSTALLPATH)
