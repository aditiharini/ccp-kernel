#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include "bpf.h"
#include "libbpf.h"
#include "bpf_load.h"
#include "perf-sys.h"
#include "trace_helpers.h"

static int perf_fd;

static int print_output(void * data, int size) {
	struct {
		__s32 delivered;
		__s32 rtt_us;
		__s32 losses;
		__u32 acked_sacked;	
	} *e = data;
	printf("EVENT\n");
	printf("delivered: %d\n", e->delivered);
	printf("rtt_us: %d\n", e->rtt_us);
	printf("losses: %d\n", e->losses);
	printf("acked_sacked: %d\n", e->acked_sacked);
	return LIBBPF_PERF_EVENT_CONT;
}

static void init(void) {
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,	
	};

	perf_fd = sys_perf_event_open(&attr, -1, 0, -1, 0);
	int key = 0;

	assert(perf_fd >= 0);
	assert(bpf_map_update_elem(map_fd[0], &key, &perf_fd, BPF_ANY) == 0);
	ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

int main(int argc, char **argv) {
	FILE *f;
	int ret;
	int cg_fd = 0;

	cg_fd = open("/tmp/cgroupv2/foo", O_DIRECTORY, O_RDONLY);
	if (load_bpf_file("../bpf/bpf_perf_kern.o")) {
		printf("could not load %s\n", bpf_log_buf);
		return 1;
	}

	if (bpf_prog_attach(prog_fd[0], cg_fd, BPF_CGROUP_SOCK_OPS, 0)) {
		printf("couldn't load program");
	}

	init();

	if (perf_event_mmap(perf_fd) < 0) {
		printf("error with mmap\n");
	}

	f = popen("taskset 1 dd if=/dev/zero of=/dev/null", "r");
	(void) f;

	ret = perf_event_poller(perf_fd, print_output);
	kill(0, SIGINT);
	return ret;

}
