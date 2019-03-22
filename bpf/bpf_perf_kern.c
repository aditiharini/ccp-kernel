#include <linux/ptrace.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

struct ccp_data {
	s32 delivered;
	s32 rtt_us;
	s32 losses;
	u32 acked_sacked;
};

struct bpf_map_def SEC("maps") ccp_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1000,
};

SEC("sockops")
int send_ccp_data(struct bpf_sock_ops * skops) {
	struct ccp_data data = {skops->args[0], skops->args[1], skops->args[2], skops->args[3]};
	//struct ccp_data data = {0, 0, 0, 0};
	bpf_perf_event_output(skops, &ccp_events, 0, &data, sizeof(data));
	skops->reply = 0;
	return 1;
	
}

char _license[] SEC("license") = "GPL";
