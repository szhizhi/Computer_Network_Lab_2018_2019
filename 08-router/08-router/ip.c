#include "ip.h"
#include "icmp.h"
#include "rtable.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void forward_ip_packet(u32 ip_dst, char *packet, int len)
{
	//fprintf(stderr, "TODO: forward ip packet.\n");
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);

	//ttl-1
	ip_hdr->ttl--;
	if(ip_hdr->ttl <= 0) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}

	ip_hdr->checksum = ip_checksum(ip_hdr); // reset the checksum

	rt_entry_t *entry = longest_prefix_match(ip_dst);

	if(entry != NULL) {
		printf("entry != NULL!, ip_dst = %x, entry->if_name = %s\n",ip_dst, entry->if_name);
		ip_send_packet(packet, len);
	}
	else {
		printf("entry = NULL!\n");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
	}
}

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip_hdr->daddr);
	struct icmphdr *icmp_hdr = (struct icmphdr*)((char*)ip_hdr + IP_HDR_SIZE(ip_hdr));

	fprintf(stderr, "TODO: handle ip packet. iface_name = %s, daddr = %x\n", iface->name, daddr);

	if(daddr == iface->ip && icmp_hdr->type == ICMP_ECHOREQUEST) {
		icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		free(packet);
		return;
	}
	else {
		forward_ip_packet(daddr, packet, len);
		return;
	}
}


