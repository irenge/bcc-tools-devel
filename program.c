#undef KBUILD_MODNAME 
#define KBUILD_MODNAME "program"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//BPF_PERCPU_ARRAY(packetcnt, uint32_t, 32);

BPF_TABLE("percpu_array", uint32_t, long, packetcnt, 256);

int drop_packets_count(struct xdp_md *ctx) {
	
	int ipsize = 0;
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	struct iphdr *ip;
	
	long *cnt;
	__u32 idx;

	ipsize = sizeof(*eth);
	ip = data + ipsize;
	ipsize += sizeof(struct iphdr);

	if (data + ipsize > data_end){
			return XDP_ABORTED;
			}
	
	idx = ip->protocol;
        cnt = packetcnt.lookup(&idx);
	
	if (ip->protocol == IPPROTO_TCP) {

		if (cnt) {
			*cnt += 1;
		}

		return XDP_DROP;
	}


	
	return XDP_PASS;
}
