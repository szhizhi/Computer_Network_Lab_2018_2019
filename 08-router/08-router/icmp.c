#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	printf( "TODO: malloc and send icmp packet.\n");
	printf( "type = %d, code = %d.\n", type, code);

	char *packet;
	int packet_len;
	struct iphdr *ip = packet_to_ip_hdr(in_pkt);
	struct ether_header *in_eth_h = (struct ether_header*)(in_pkt);

	if (type == ICMP_ECHOREPLY){
		packet_len = len;
	}
	else {
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(ip) + 8;
	}

	packet = (char *)malloc(packet_len);
	if ( !packet ){
		printf ("Allocate failed in 'icmp_send_packet'.\n");
		exit(0);
	}
	struct ether_header *eth_h = (struct ether_header *)(packet);
	memcpy(eth_h->ether_dhost, in_eth_h->ether_dhost, ETH_ALEN);
	memcpy(eth_h->ether_shost, in_eth_h->ether_dhost, ETH_ALEN);
	eth_h->ether_type = htons(ETH_P_IP);

	struct iphdr *iph = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	rt_entry_t *entry = longest_prefix_match(ntohl(ip->saddr));
	ip_init_hdr(iph, entry->iface->ip, ntohl(ip->saddr), packet_len-ETHER_HDR_SIZE, 1);

	struct icmphdr *icmp = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	if (type == ICMP_ECHOREPLY) {
		icmp->type = 0;
		icmp->code = 0;
		char *packet_rest = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE - 4;
		char *in_pkt_rest = (char *)(in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ip) + ICMP_HDR_SIZE - 4);
		int data_size = len - ETHER_HDR_SIZE - IP_HDR_SIZE(ip) - ICMP_HDR_SIZE + 4;
		memcpy(packet_rest, in_pkt_rest, data_size);
		icmp->checksum = icmp_checksum(icmp, data_size + ICMP_HDR_SIZE - 4);
	}
	else {
		printf("icmp_send_packet is NOT ICMP_ECHOREPLY\n");
		icmp->type = type;
		icmp->code = code;
		char *packet_rest = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE;
		memset(packet_rest - 4, 0, 4);
		int data_size = IP_HDR_SIZE(ip) + 8;
		memcpy(packet_rest, ip, data_size);
		icmp->checksum = icmp_checksum(icmp, data_size + ICMP_HDR_SIZE);
	}

	ip_send_packet(packet, packet_len);
	//printf("size = %d\n", packet_len);
	//printf("%s", packet); while(1);
}