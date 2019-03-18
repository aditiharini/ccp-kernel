OBJS = trace_output_kern.o bpf_perf_kern.o

LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -O2 -emit-llvm

# In case up-to-date headers are not installed locally in /usr/include,
# use source build.

linuxhdrs ?= /usr/src/kernels/`uname -r`

LINUXINCLUDE =  -I ../../linux-fork/usr/include \
				-I ../../linux-fork/tools/lib \
				-I ../../linux-fork/tools/testing/selftests/bpf \
				-I ../../linux-fork/tools/perf \
				-I ../../linux-fork/tools/lib/bpf \

prefix ?= /usr/local

INSTALLPATH = $(prefix)/lib/bpf

install_PROGRAM = install
install_DIR = install -dv

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
                -I../include $(LINUXINCLUDE) \
                $(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

install: $(OBJS)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_PROGRAM) $^ -t $(INSTALLPATH)

uninstall: $(OBJS)
	rm -rf $(INSTALLPATH)
