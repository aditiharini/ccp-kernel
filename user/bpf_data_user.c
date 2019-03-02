/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include "bpf_load.h"

int main(int argc, char **argv)
{
	int key = 0;
	int value = -1;
	int cg_fd = 0;
	cg_fd = open("/tmp/cgroupv2/foo", O_DIRECTORY, O_RDONLY);
	if (load_bpf_file("../bpf/bpf_data_kern.o")) {
		printf("couldn't load file: %s\n", bpf_log_buf);
		return 0;
	}
	if (bpf_prog_attach(prog_fd[0], cg_fd, BPF_CGROUP_SOCK_OPS, 0)) {
		printf("couldn't load program\n");
	}
	while (value == -1) {
		bpf_map_lookup_elem(map_fd[0], &key, &value);
	}

	printf("send_cwnd: %d\n", value);

	return 0;
}
