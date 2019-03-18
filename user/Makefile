COMMONOBJS = bpf.o str_error.o nlattr.o btf.o bpf_load.o trace_helpers.o libbpf.o
LOADPROG = load_sock_ops
TRACEPROG = trace_output_user
CCPPROG = bpf_perf_user

LOADOBJ = $(LOADPROG).o
TRACEOBJ = $(TRACEPROG).o
CCPOBJ = $(CCPPROG).o

PROGS= $(LOADPROG) $(TRACEPROG) $(CCPPROG)
OBJS= $(COMMONOBJS) $(LOADOBJ) $(TRACEOBJ) $(CCPOBJ)


linuxhdrs ?= /usr/src/linux-headers-4.19.0-041900

LINUXINCLUDE =  -I ../../linux-fork/tools/lib \
				-I ../../linux-fork/tools/testing/selftests/bpf \
				-I ../../linux-fork/tools/perf \
				-I ../../linux-fork/tools/lib/bpf \
				-I ../../linux-fork/tools/include \
				-I ../../linux-fork/arch/x86/include \
				-I ../../linux-fork/arch/x86/include/generated \
				-I ../../linux-fork/usr/include \


prefix ?= /usr/local

INSTALLPATH = $(prefix)/bin

install_PROGRAM = install
install_DIR = install -d

LDLIBS = -lelf -lrt

all: $(LOADPROG) $(TRACEPROG) $(CCPPROG)

.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)

%.o: %.c
	$(CC) -g -Wno-unused-variable $(LINUXINCLUDE) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJS)
	$(CC) -g -o $@ $(@).o $(COMMONOBJS) $(CFLAGS) $(LDLIBS)

install: $(PROGS)
	$(install_DIR) -d $(INSTALLPATH) ; \
    $(install_PROGRAM) $^ -t $(INSTALLPATH)

uninstall: $(PROGS)
	cd $(INSTALLPATH); rm -f $^
