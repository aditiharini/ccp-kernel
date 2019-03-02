/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set initial congestion window and initial receive
 * window to 40 packets and send and receive buffers to 1.5MB. This
 * would usually be done after doing appropriate checks that indicate
 * the hosts are far enough away (i.e. large RTT).
 *
 * Use load_sock_ops to load this BPF program.
 */

#include <linux/socket.h>
#include <linux/types.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

#define DEBUG 1

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct bpf_data {
    __s32 delivered;
    long rtt_us;
    int losses;
    __u32 acked_sacked;
};

struct bpf_map_def SEC("maps") data_map = {
	.type = BPF_MAP_TYPE_HASH, 
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32), 
	.max_entries = 1000, 
};

SEC("sockops")
int bpf_iw(struct bpf_sock_ops *skops)
{
	int bufsize = 1500000;
	int rv = 0;
	int op;
	struct bpf_data data = {skops->args[0], skops->args[1], skops->args[2], skops->args[3]};
	__u32 i = 0;	

	// For the POC, we will just transfer values directly without performing any calculations on them as is done in the kernel 

	bpf_map_update_elem(&data_map, &i, &data.delivered, BPF_ANY);
	i++;
	bpf_map_update_elem(&data_map, &i, &data.rtt_us, BPF_ANY);
	i++;
	bpf_map_update_elem(&data_map, &i, &data.losses, BPF_ANY);
	i++;
	bpf_map_update_elem(&data_map, &i, &data.acked_sacked, BPF_ANY);

	op = (int) skops->op;
	bpf_printk("delivered %d\n", data.delivered);

#ifdef DEBUG
	bpf_printk("BPF command: %d\n", op);
#endif

#ifdef DEBUG
	bpf_printk("Returning %d\n", rv);
#endif
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
