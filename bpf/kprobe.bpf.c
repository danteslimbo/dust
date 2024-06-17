#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_ipv6.h"

struct config {
  u32 pid;
}  __attribute__((packed));

static volatile const struct config CFG;
#define cfg (&CFG)

struct event_t {
  u32 pid;
  u32 cpu_id;
  u64 ts;
  u64 addr;
  u64 req;
} __attribute__((packed));

#define MAX_QUEUE_ENTRIES 10000
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct event_t);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

#define MAX_TRACK_SIZE 4096
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, u32);
  __uint(max_entries, MAX_TRACK_SIZE);
} request_map SEC(".maps");

static __always_inline int
kprobe_request(struct request* req, struct pt_regs* ctx) {
  struct event_t event = {};
  u64 key = (u64)req;
  u32 *exists = bpf_map_lookup_elem(&request_map, &key);
  if (!exists)
    return BPF_OK;

  event.addr = PT_REGS_IP(ctx);
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.ts = bpf_ktime_get_ns();
  event.cpu_id = bpf_get_smp_processor_id();
  event.req = key;

  bpf_map_push_elem(&events, &event, BPF_EXIST);
  return BPF_OK;
}

#define dust_KPROBE_TYPE "kprobe"

#define dust_ADD_KPROBE(X)                                                      \
  SEC(dust_KPROBE_TYPE "/skb-" #X)                                              \
  int kprobe_dust_##X(struct pt_regs *ctx) {                                    \
    struct request *req = (struct request *) PT_REGS_PARM##X(ctx);              \
    return kprobe_request(req, ctx);                                            \
  }

dust_ADD_KPROBE(1)
dust_ADD_KPROBE(2)
dust_ADD_KPROBE(3)
dust_ADD_KPROBE(4)
dust_ADD_KPROBE(5)

SEC("kretprobe/alloc_request")
int BPF_KRETPROBE(alloc, u64 req) {
  if (cfg->pid > 0 && bpf_get_current_pid_tgid() >> 32 != cfg->pid) {
    bpf_printk("cfg->pid %d, pid %d\n", cfg->pid, bpf_get_current_pid_tgid() >> 32);
    return BPF_OK;
  }

  u32 val = 1;
  bpf_map_update_elem(&request_map, &req, &val, BPF_ANY);

  struct event_t event = {};
  event.addr = PT_REGS_IP(ctx);
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.ts = bpf_ktime_get_ns();
  event.cpu_id = bpf_get_smp_processor_id();
  event.req = (u64)req;
  bpf_map_push_elem(&events, &event, BPF_EXIST);

  return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
