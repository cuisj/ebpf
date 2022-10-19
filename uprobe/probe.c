//go:build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1 << 24
};

SEC("uprobe/main")
int trace_main(struct pt_regs *ctx)
{
	struct event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!ev)
		return 0;

	ev->pid = bpf_get_current_pid_tgid();

	bpf_ringbuf_submit(ev, 0);

	return 0;
}
