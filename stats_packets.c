#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>

BPF_TABLE("percpu_array", uint32_t, long, packetcntd, 256);
BPF_TABLE("percpu_array", uint32_t, long, packetcntp, 256);

struct hdr_cursor {
	void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
		void *data_end,
		struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}
/*
   static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
   {

   struct iphdr *iph = nh->pos;
   int hdrsize = iph->ihl * 4;

//if ((iph + 1 ) > data_end)
//      return -1;

//hdrsize = iph->ihl * 4;

if ((iph + hdrsize ) > data_end)
return -1;

// Sanity check packet field is valid 
if(hdrsize < sizeof(*iph))
return -1;

// Variable-length IPv4 header, need to use byte-based arithmetic 
if (nh->pos + hdrsize > data_end)
return -1;

nh->pos += hdrsize;
 *iphdr = iph;

 return iph->protocol;

 }
 */

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	if (ip6h + 1 > data_end)
		return -1;
	nh->pos = ip6h + 1;
	*ipv6hdr = ip6h;

	return ip6h->nexthdr;



}
int packets_count(struct xdp_md *ctx) {

	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;

	long * cntd, *cntp;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);

	if (eth_type < 0)
		return XDP_ABORTED;

	cntd= packetcntd.lookup(&eth_type);
	cntp= packetcntp.lookup(&eth_type);

	if (!cntd || !cntp)
		return XDP_ABORTED;
	if (eth_type == bpf_htons(ETH_P_IPV6)) {

		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);

		if (cntd)
			*cntd += 1;
		return XDP_DROP;
	} else {

		if (cntp)
			*cntp += 1;
		return XDP_PASS;


	}
}

/*

   if (eth_type == bpf_htons(ETH_P_IP)) {

   ip_type =parse_iphdr(&nh, data_end, &iphdr);

   cntp= packetcntp.lookup(&ip_type);

   if (cntd) {
 *cntd += 1;
 }
 return XDP_DROP;

 }


 return XDP_PASS;
 }
 */






//}
