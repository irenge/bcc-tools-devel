#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

BPF_TABLE("percpu_array", uint32_t, long, packetcntd, 256);
BPF_TABLE("percpu_array", uint32_t, long, packetcntp, 256);

/*
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
*/


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

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
        struct iphdr *iph = nh->pos;
        int hdrsize = 0;

/*        if (iph + 1 > data_end)
                return -1;
*/
        hdrsize = iph->ihl * 4;
        /* Sanity check packet field is valid */
        if(hdrsize < sizeof(*iph))
                return -1;

        /* Variable-length IPv4 header, need to use byte-based arithmetic */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *iphdr = iph;

        return iph->protocol;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
        int len;
        struct udphdr *h = nh->pos;

        if (h + 1 > data_end)
                return -1;

        nh->pos  = h + 1;
        *udphdr = h;

        len = bpf_ntohs(h->len) - sizeof(struct udphdr);
        if (len < 0)
                return -1;

        return len;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct tcphdr **tcphdr)
{
        int len;
        struct tcphdr *h = nh->pos;

        if (h + 1 > data_end)
                return -1;

        len = h->doff * 4;
        /* Sanity check packet field is valid */
        if(len < sizeof(*h))
                return -1;

        /* Variable-length TCP header, need to use byte-based arithmetic */
        if (nh->pos + len > data_end)
                return -1;

        nh->pos += len;
        *tcphdr = h;

        return len;
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

		/*if (cntd)
			*cntd += 1;
		return XDP_DROP;
		*/
	} else if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else {
		if (cntd)
                        *cntd += 1;

		return XDP_DROP;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			return XDP_ABORTED;
		}
		//udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);

	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
                        //action = XDP_ABORTED;
                        //goto out;
                } else {
			tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
		}

	}

	if (cntp)
			*cntp += 1;
		return XDP_PASS;



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
