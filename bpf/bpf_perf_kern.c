#include <linux/ptrace.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct connection_info {
	u32 local_port;
	u32 remote_port;
	u32 local_ip4;
	u32 remote_ip4;
	u32 sock_id;
};

struct connection_state {
	u64 last_bytes_acked;
	u32 last_sacked_out;
	struct connection_info conn_info;
};

struct ccp_data {
	s32 lost_pkts_sample;
	s32 rtt_sample_us;
	u32 was_timeout;
	u32 packets_misordered;
	u32 bytes_acked;
	u32 packets_in_flight;
	struct connection_info conn_info;
};

struct bpf_map_def SEC("maps") ccp_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1000,
};

struct bpf_map_def SEC("maps") ccp_sock_state = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(struct connection_state),
	.max_entries = 4096,
};

static int tcp_left_out(struct bpf_sock_ops* skops) {
	return skops->sacked_out + skops->lost_out;
}

static int tcp_packets_in_flight(struct bpf_sock_ops* skops) {
	return skops->packets_out - tcp_left_out(skops) + skops->retrans_out;	
}

static bool is_equal(struct connection_info c1, struct connection_info c2) {
	return c1.local_port == c2.local_port 
	&& c1.local_ip4 == c2.local_ip4
	&& c1.remote_port == c2.remote_port
	&& c1.remote_ip4 == c2.remote_ip4;
}

static void memset(int value, int* start, int size) {
	for (int i = 0; i < size; i++) {
		*(start + i) = value;
	}
}
// Measurements needed: 
// - packets_in_flight = tp.mss_cache * tcp_packets_in_flight(skops)
// - rtt_sample_us- rs->rtt_us (arg)
// - bytes_acked- tp.bytes_acked, maintain last_bytes_acked
// - packets_misordered- tp.sacked_out, maintain last_sacked_out
// - lost_pkts_sample- rs->losses (arg)
// - was_timeout- ca->dp->prins.was_timeout

SEC("sockops")
int send_ccp_data(struct bpf_sock_ops* skops) {
	if (skops->args[0] == 0 && skops->args[1] == 0 && skops->args[2] == 0 && skops->args[3] == 0) {
		bpf_printk("didn't come from kernel mod\n");
		return 1;
	}
	u32 sock_id = skops->args[3];
	struct connection_state* conn_state = (struct connection_state*) bpf_map_lookup_elem(&ccp_sock_state, &sock_id);
	struct connection_info conn_info = {
		skops->local_port,
		skops->remote_port,
		skops->local_ip4,
		skops->remote_ip4,
		sock_id,
	};
	if (!conn_state || !is_equal(conn_info, conn_state->conn_info)) {
		struct connection_state new_conn_state = {
			0,
			0,
			conn_info,
		};
		conn_state = &new_conn_state;
	}
	struct ccp_data data = {
		skops->args[0], 
		skops->args[1], 
		skops->args[2], 
		skops->sacked_out - conn_state->last_sacked_out,
		skops->bytes_acked - conn_state->last_bytes_acked,
		skops->mss_cache * tcp_packets_in_flight(skops),
		conn_info,	
	};
	
	u64 ret = bpf_perf_event_output(skops, &ccp_events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	struct connection_state new_conn_state = {
		skops->bytes_acked,
		skops->sacked_out,
		conn_info,
	};
	bpf_map_update_elem(&ccp_sock_state, &sock_id, &new_conn_state, 0);
	
	if (ret != 0){
		bpf_printk("ret val %d\n", ret);
	}
	skops->reply = 0;
	return 1;
	
}

char _license[] SEC("license") = "GPL";
