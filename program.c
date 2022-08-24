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
BPF_TABLE("percpu_array", uint32_t, long, packetcntp, 256);
BPF_TABLE("percpu_array", uint32_t, long, packetcntx, 256);


int packets_count(struct xdp_md *ctx) {

	int ipsize = 0;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;

	struct udphdr *udphdr;
        struct tcphdr *tcphdr;


	long *cntd, *cntp, *cntx;

	__u32 ip_type, eth_type;

	ipsize = sizeof(*eth);
	iphdr = data + ipsize;
	ipsize += sizeof(struct iphdr);

	
	if (data + ipsize > data_end){

		return XDP_ABORTED;
	}


	ip_type = iphdr->protocol;
	
	cntd = packetcntd.lookup(&ip_type);
	cntp= packetcntp.lookup(&ip_type);
	cntx= packetcntx.lookup(&ip_type);

	
	if(!cntd || !cntp || !cntx) {
	
		return  XDP_ABORTED;
	}
	
	if (ip_type == IPPROTO_TCP) {

		if (cntp) {
			*cntp += 1;
		}

		return XDP_PASS;
	} else if (ip_type == IPPROTO_UDP) {
		if (cntd) {
                        *cntd += 1;
                }

                return XDP_DROP;
	}

        if (cntx) 
		*cntx += 1;

	return XDP_TX;
}
