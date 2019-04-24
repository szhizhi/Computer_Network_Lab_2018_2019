#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources whRen exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	//fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	//printf("arpcache_lookup\n");
	int i = 0;
	pthread_mutex_lock(&arpcache.lock);

	//printf("arpcache_lookup_1\n");

	for (i = 0; i < MAX_ARP_SIZE; i++ ) {
		//printf("arpcache_lookup i = %d\n", i);
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			printf("arpcache_lookup i = %d\n", i);
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	//fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	printf("arpcache_append_packet iface_name = %s, ip4 = %x.\n", iface->name, ip4);
	pthread_mutex_lock(&arpcache.lock);

	struct cached_pkt *new_pkt = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	if ( !new_pkt ){
		printf ("Allocate failed in 'arpcache_append_packet'.\n");
		exit(0);
	}
	init_list_head(&new_pkt->list);
	new_pkt->len = len;
	new_pkt->packet = packet;

	struct arp_req *p, *q;
	list_for_each_entry_safe(p, q, &arpcache.req_list, list){
		if(p->iface == iface && p->ip4 == ip4){
			list_add_tail(&new_pkt->list, &(p->cached_packets));
			pthread_mutex_unlock(&arpcache.lock);
			// There is already an entry with the same IP address and iface
			return;
		}
	}

	// NOT FIND
	struct arp_req *new_req = (struct arp_req *)malloc(sizeof(struct arp_req));
	if (!new_req){
		printf("Allocate memory(new_req) falied in 'arpcache_append_packet'.\n");
		exit(0);
	}
	init_list_head(&new_req->list);
	init_list_head(&new_req->cached_packets);

	new_req->iface = iface;
	new_req->ip4 = ip4;
	new_req->sent = time(NULL);
	new_req->retries = 0;
	list_add_head(&new_pkt->list, &new_req->cached_packets); // Add the pkt to cached_packets
	list_add_tail(&new_req->list, &arpcache.req_list);       // Add the req to req_list

	pthread_mutex_unlock(&arpcache.lock);

	arp_send_request(iface, ip4);
	return;	
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	//fprintf(stderr, "TODO: arpcache_insert, ip4 = %x.\n", ip4);
	pthread_mutex_lock(&arpcache.lock);

	int i = 0;
	// Find an invalid entry. If there's not any invalid entry, i = MAX_ARP_SIZE.
	for(i = 0; i < MAX_ARP_SIZE - 1; i++) {
		if(arpcache.entries[i].valid == 0)
			break;
	}
	
	arpcache.entries[i].ip4 = ip4;
	memcpy(arpcache.entries[i].mac, mac, ETH_ALEN);
	arpcache.entries[i].added = time(NULL);
	arpcache.entries[i].valid = 1;

	printf("TODO: arpcache_insert: ip4 = %x insert i = %d!\n", ip4, i);

	struct arp_req *req_p, *req_q;
	list_for_each_entry_safe(req_p, req_q, &arpcache.req_list, list) { // Find the corresponding req_list
		if (req_p->ip4 == ip4) {
			//printf("ip4 = %x\n", req_p->ip4);
			struct cached_pkt *pkt_p, *pkt_q;
			list_for_each_entry_safe(pkt_p, pkt_q, &req_p->cached_packets, list){
				printf("iface_name = %s\n", req_p->iface->name);
				pthread_mutex_unlock(&arpcache.lock); // Remember
				iface_send_packet_by_arp(req_p->iface, ip4, pkt_p->packet, pkt_p->len);
				pthread_mutex_lock(&arpcache.lock);
				list_delete_entry(&pkt_p->list);
				free(pkt_p);
			}
			//free(req_p->iface);
			list_delete_entry(&req_p->list);
			free(req_p);
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	//printf("insert success!\n");
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	int i;
	struct arp_req *req_p, *req_q;
	struct cached_pkt *pkt_p, *pkt_q;

	while (1) {
		sleep(1);
		//fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		pthread_mutex_lock(&arpcache.lock);
		
		// check the IP->mac entry
		for(i = 0; i < MAX_ARP_SIZE; i++) {
			if( time(NULL) - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT)
				arpcache.entries[i].valid = 0;
		}

		// check the packet
		list_for_each_entry_safe(req_p, req_q, &arpcache.req_list, list) {
			if(req_p->retries > ARP_REQUEST_MAX_RETRIES) {
				list_for_each_entry_safe(pkt_p, pkt_q, &req_p->cached_packets, list){
					printf("Arpcache_sweep req_p->retries > ARP_REQUEST_MAX_RETRIES!\n");
					pthread_mutex_unlock(&arpcache.lock);	// Remember!
					icmp_send_packet(pkt_p->packet, pkt_p->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					pthread_mutex_lock(&arpcache.lock);
					free(pkt_p->packet);
					list_delete_entry(&pkt_p->list);
					free(pkt_p);
				}
				//free(req_p->iface);
				list_delete_entry(&req_p->list);
				free(req_p);
			}
			else {
				printf("req_p->retries = %d\n", req_p->retries);
				arp_send_request(req_p->iface, req_p->ip4);
				req_p->sent = time(NULL);
				req_p->retries ++;
			}
			
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}