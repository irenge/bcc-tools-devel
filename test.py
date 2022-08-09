#!/usr/bin/env python3

from bcc import BPF
bpf_text = """
#include <net/inet_sock.h>
#include <net/sock.h>

#define MAX_DNS 512

struct dns_data_t {
    u8  pkt[MAX_DNS];
};

BPF_PERF_OUTPUT(dns_events);

// single element per-cpu array to hold the current event off the stack
BPF_PERCPU_ARRAY(dns_data, struct dns_data_t, 1);

int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);

    // 13568 = ntohs(53);
    if (is->inet_sport == 13568 || is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);

        size_t buflen = (size_t)msghdr->msg_iter.iov->iov_len;

        if (buflen > MAX_DNS)
            buflen = MAX_DNS;

        u32 zero = 0;
        struct dns_data_t *data = dns_data.lookup(&zero);
        if (!data)
            return 0;

        void *iovbase = msghdr->msg_iter.iov->iov_base;
        bpf_probe_read(data->pkt, buflen, iovbase);
        //dns_events.perf_submit(ctx, data, buflen);

        u16 dport = sk->__sk_common.skc_dport;
        dns_events.perf_submit_skb(ctx, buflen, &dport, sizeof(dport));
        bpf_trace_printk("trace_udp_sendmsg: dport = %d", ntohs(dport));
    }
    return 0;
}
"""

def print_dns(cpu, data, size):
    print('print_dns()')

b = BPF(text=bpf_text)
b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

print("Tracing connect ... Hit Ctrl-C to end")

b["dns_events"].open_perf_buffer(print_dns)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
