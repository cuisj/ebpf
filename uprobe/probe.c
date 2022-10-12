//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = 4,
	.value_size = 4
};

SEC("uprobe/main")
int trace_main(struct pt_regs *ctx)
{
	struct event ev;
	ev.pid = bpf_get_current_pid_tgid();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

	return 0;
}
