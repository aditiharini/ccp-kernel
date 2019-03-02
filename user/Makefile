COMMONOBJS = bpf.o bpf_load.o nlattr.o

CCPPROG = bpf_data_user
LOADPROG = load_sock_ops
CCPOBJ = $(CCPPROG).o
LOADOBJ = $(LOADPROG).o
PROGS= $(CCPPROG) $(LOADPROG)
OBJS= $(COMMONOBJS) $(CCPOBJ) $(LOADOBJ)

linuxhdrs ?= /usr/src/linux-headers-4.19.0-041900

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include \

prefix ?= /usr/local

INSTALLPATH = $(prefix)/bin

install_PROGRAM = install
install_DIR = install -d

LDLIBS = -lelf

all: $(CCPPROG) $(LOADPROG)

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
