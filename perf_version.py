from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
//BPF_HASH(last);
BPF_PERCPU_HASH(last);
struct data_t {
u64 ts;
u64 delta;
};

BPF_PERF_OUTPUT(events);

int drop_packets_count(struct pt_regs *ctx) {
    struct data_t data_s = {};

    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }

        data_s.ts = bpf_ktime_get_ns();
        data_s.delta = delta / 1000000;
        events.perf_submit(ctx, &data_s, sizeof(data_s));

        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="drop_packets_count")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
def print_event(cpu, data_s, size):
    global start
    event = b["events"].event(data_s)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (time_s,   event.delta))
# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

