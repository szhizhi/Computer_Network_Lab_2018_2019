#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	//fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	printf("arp_send_request iface_name = %s, dest_ip = %x\n", iface->name, dst_ip);

	int len_packet = sizeof(struct ether_arp) + ETHER_HDR_SIZE;
	char *new_pkt = (char *) malloc (len_packet);
	if ( !new_pkt ){
		printf ("Allocate failed in 'arp_send_request'.\n");
		exit(0);
	}

	struct ether_header *eth_h = (struct ether_header *)(new_pkt);
	struct ether_arp *eth_arp = (struct ether_arp *)(new_pkt + ETHER_HDR_SIZE);

	// set the Dest and Src Ether Addr
	memcpy(eth_h->ether_shost, iface->mac, ETH_ALEN);
	memset(eth_h->ether_dhost, 0xff, ETH_ALEN); // Broadcast

	// set ARP
	eth_h->ether_type = htons(ETH_P_ARP);
	eth_arp->arp_hrd  = htons(ARPHRD_ETHER);
	eth_arp->arp_pro  = htons(ETH_P_IP);
	eth_arp->arp_hln  = 6;
	eth_arp->arp_pln  = 4;
	eth_arp->arp_op   = htons(ARPOP_REQUEST);
	memcpy(eth_arp->arp_sha, iface->mac, ETH_ALEN);
	eth_arp->arp_spa = htonl(iface->ip);
	memset(eth_arp->arp_tha, 0, ETH_ALEN);
	eth_arp->arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, new_pkt, len_packet);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");

	int len_packet = sizeof(struct ether_arp) + ETHER_HDR_SIZE;
	char *new_pkt = (char *) malloc(len_packet);
	if ( !new_pkt ){
		printf ("Allocate failed in 'arp_send_reply'.\n");
		exit(0);
	}
	struct ether_header *eth_h = (struct ether_header *) (new_pkt);
	struct ether_arp *eth_arp = (struct ether_arp *)(new_pkt + ETHER_HDR_SIZE);

	// set the Dest and Src Ether Addr
	memcpy(eth_h->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eth_h->ether_shost, iface->mac, ETH_ALEN);

	// set ARP
	eth_h->ether_type = htons(ETH_P_ARP);
	eth_arp->arp_hrd  = htons(ARPHRD_ETHER);
	eth_arp->arp_pro  = htons(ETH_P_IP);
	eth_arp->arp_hln  = 6;
	eth_arp->arp_pln  = 4;
	eth_arp->arp_op   = htons(ARPOP_REPLY);
	memcpy(eth_arp->arp_sha, iface->mac, ETH_ALEN);
	eth_arp->arp_spa = htonl(iface->ip);
	memcpy(eth_arp->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	eth_arp->arp_tpa = req_hdr->arp_spa;

	iface_send_packet(iface, new_pkt, len_packet);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	//fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *eth_arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	fprintf(stderr, "TODO: process arp packet, iface_name = %s, OP = %d.\n", iface->name, ntohs(eth_arp->arp_op));

	if (ntohs(eth_arp->arp_op) == ARPOP_REQUEST) {
		if (ntohl(eth_arp->arp_tpa) == iface->ip) {
			printf("eth_arp->arp_tpa = %x \n", iface->ip);
			//while(1);
			arpcache_insert(ntohl(eth_arp->arp_spa), eth_arp->arp_sha);
			arp_send_reply(iface, eth_arp);
		}
	}
	else if (ntohs(eth_arp->arp_op) == ARPOP_REPLY) {
			printf("eth_arp->arp_tpa = %x \n", ntohs(eth_arp->arp_tpa));
			arpcache_insert(ntohl(eth_arp->arp_spa), eth_arp->arp_sha);
	}
	else
		printf ("Unknown ARP_OP.\n");
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	//printf("iface_send_packet_by_arp\n");

	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];

	//printf("iface_send_packet_by_arp_1\n");

	int found = arpcache_lookup(dst_ip, dst_mac);

	//printf("iface_send_packet_by_arp_2\n");


	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		printf("iface_send_packet_by_arp iface_name = %s, dest_ip = %x\n", iface->name, dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
		//printf("name = %s\n", iface->name);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		printf("iface_send_packet_by_arp NOT FOUND\n");
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
