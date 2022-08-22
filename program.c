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

BPF_TABLE("percpu_array", uint32_t, long, packetcntd, 256);

int packets_count(struct xdp_md *ctx) {

	int ipsize = 0;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;


	long *cntd;

	__u32 ip_type;

	ipsize = sizeof(*eth);
	iphdr = data + ipsize;
	ipsize += sizeof(struct iphdr);

	if (data + ipsize > data_end){

		return XDP_ABORTED;
	}

	ip_type = iphdr->protocol;
	
	cntd = packetcntd.lookup(&ip_type);
	
	if(!cntd) {
	
		return  XDP_ABORTED;
	}
	
	if (ip_type == IPPROTO_TCP) {

		if (cntd) {
			*cntd += 1;
		}

		return XDP_DROP;
	}



	return XDP_PASS;
}
