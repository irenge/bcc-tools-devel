from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

struct data_t {
    u64 ts;
    u64 delta;
    u64 count;
};

BPF_PERF_OUTPUT(trace_result);

int do_trace(struct pt_regs *ctx) {
    
    u64 ts, *tsp, delta, key=0,index=1, count= 1;
    struct data_t data;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
         tsp = last.lookup(&index);
            if (tsp != NULL) {
                count += *tsp;
            bpf_trace_printk("%d\\n", delta / 1000000);
            }
           
        }

        data.ts = bpf_ktime_get_ns();
        data.delta = delta / 1000000;
        data.count = count;
        trace_result.perf_submit(ctx, &data, sizeof(data));
        last.delete(&key);
        last.delete(&index);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    last.update(&index, &count);

    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
def print_data(cpu, data, size):
    global start
    event = b["trace_result"].event(data)
    if start == 0:
        start = event.ts
    ts = ((float) (event.ts - start)) / 1000000000
    print("At time %.2f s: %s syncs detected, last %s ms ago" % (ts, event.count,  event.delta))

b["trace_result"].open_perf_buffer(print_data)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

