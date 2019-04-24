#include "ip.h"
#include "icmp.h"
#include "packet.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

// #include "log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// initialize ip header 
void ip_init_hdr(struct iphdr *ip, u32 saddr, u32 daddr, u16 len, u8 proto)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons(len);
	ip->id = rand();
	ip->frag_off = htons(IP_DF);
	ip->ttl = DEFAULT_TTL;
	ip->protocol = proto;
	ip->saddr = htonl(saddr);
	ip->daddr = htonl(daddr);
	ip->checksum = ip_checksum(ip);
}

// lookup in the routing table, to find the entry with the same and longest prefix.
// the input address is in host byte order
rt_entry_t *longest_prefix_match(u32 dst)
{
	//fprintf(stderr, "TODO: longest prefix match for the packet.\n");
	rt_entry_t *pos, *maxpos = NULL;
	u32 maxmask = 0;
	list_for_each_entry(pos, &rtable, list){
		u32 ip = dst & pos->mask;
		u32 pos_ip = pos->dest & pos->mask;
		if ( pos_ip == ip && pos->mask > maxmask ) {
			maxpos = pos;
			maxmask = pos->mask;
		}
	}
	return maxpos;
}

// send IP packet
//
// Different from forwarding packet, ip_send_packet sends packet generated by
// router itself. This function is used to send ICMP packets.
void ip_send_packet(char *packet, int len)
{
	//fprintf(stderr, "TODO: send ip packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	rt_entry_t *entry = longest_prefix_match(daddr);
	if (entry == NULL) {
		printf("No corresponding ip in rtable");
		return ;
	}

	u32 next_hop = entry->gw;
	if (!next_hop)
		next_hop = daddr;

	printf("ip_send_packet  next_hop = %x\n", next_hop);

	iface_send_packet_by_arp(entry->iface, next_hop, packet, len);
}