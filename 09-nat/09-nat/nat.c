#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
    //fprintf(stdout, "TODO: determine the direction of this packet.\n");
    struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
    u32 src_addr = ntohl(ip_hdr->saddr);
    u32 dest_addr = ntohl(ip_hdr->daddr);

    rt_entry_t *src_entry = longest_prefix_match(src_addr);
    rt_entry_t *dest_entry = longest_prefix_match(dest_addr);
	
	if(src_entry->iface == nat.internal_iface && dest_entry->iface == nat.external_iface)
		return DIR_OUT;
	else if(src_entry->iface == nat.external_iface && dest_addr == nat.external_iface->ip)
		return DIR_IN;
	return DIR_INVALID;
}

u16 assign_external_port()
{
	int i;
	for(i = NAT_PORT_MIN; i < NAT_PORT_MAX; ++i) {
		if (!nat.assigned_ports[i]){
			nat.assigned_ports[i] = 1;
			break;
		}
	}
	return i;
}
void update_send_packet(char *packet, struct nat_mapping *mapping_entry, int len, int dir)
{
	struct iphdr  *ip_hdr  = packet_to_ip_hdr(packet);
	struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);

	// Update the mapping
	if(tcp_hdr->flags & TCP_FIN)
		mapping_entry->conn.external_fin = 1;
	if(tcp_hdr->flags & TCP_ACK)
		mapping_entry->conn.external_ack = 1;
	if(tcp_hdr->flags & TCP_RST) {
		mapping_entry->conn.external_fin = 1;
		mapping_entry->conn.external_ack = 1;
		mapping_entry->conn.internal_fin = 1;
		mapping_entry->conn.internal_ack = 1;
	}

	// Update and send the packet
	if(dir == DIR_OUT) {
		ip_hdr->saddr = htonl(nat.external_iface->ip);
		tcp_hdr->sport = htons(mapping_entry->external_port);
	}
	else if (dir == DIR_IN) {
		ip_hdr->daddr = htonl(mapping_entry->internal_ip);
		tcp_hdr->dport = htons(mapping_entry->internal_port);
	}
	tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
	ip_hdr->checksum = ip_checksum(ip_hdr);
	ip_send_packet(packet, len);
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	//fprintf(stdout, "TODO: do translation for this packet.\n");
	pthread_mutex_lock(&nat.lock);
	int find = 0;
	struct iphdr  *ip_hdr  = packet_to_ip_hdr(packet);
	struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);
	u32 daddr = ntohl(ip_hdr->daddr);
	u32 saddr = ntohl(ip_hdr->saddr);
	u16 sport = ntohs(tcp_hdr->sport);
	u16 dport = ntohs(tcp_hdr->dport);
	struct nat_mapping *mapping_entry, *q;

	if(dir == DIR_OUT) {
		printf("DIR_OUT\n");
		struct list_head *head = &nat.nat_mapping_list[hash8((char*)&daddr, sizeof(daddr))];
		// Find if there's already the corresponding mapping
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			if(mapping_entry->remote_ip == daddr){
				find = 1;
				break;
			}
		}

		// If not dind, build a new mapping
		if(!find) {
			struct nat_mapping *new_mapping = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
			new_mapping->remote_ip     = daddr;
			new_mapping->remote_port   = dport;
			new_mapping->internal_ip   = saddr;
			new_mapping->internal_port = sport;
			new_mapping->external_ip   = nat.external_iface->ip;
			new_mapping->external_port = assign_external_port();
			new_mapping->update_time = 0;
			memset(&new_mapping->conn, 0, sizeof(struct nat_connection));
			list_add_tail(&new_mapping->list, &mapping_entry->list);
			mapping_entry = new_mapping;
		}
	}
	else if(dir == DIR_IN) {
		printf("DIR_IN\n");
		struct list_head *head = &nat.nat_mapping_list[hash8((char*)&saddr,sizeof(saddr))];
		// Find if there's already the corresponding mapping
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			if(mapping_entry->remote_ip == saddr/* && mapping_entry->remote_port ==*/ ) {
				find = 1;
				break;
			}
		}

		// If not find, build a new mapping according to the rules	
		if(!find) {
			int rule_find = 0;
			struct dnat_rule *rule_entry, *rule_q;
			list_for_each_entry_safe(rule_entry, rule_q, &nat.rules, list) {
				if(rule_entry->external_ip == daddr && rule_entry->external_port == dport) {
					rule_find = 1;
					break;
				}
			}
			if(rule_find == 0)
				icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);

			struct nat_mapping *new_mapping = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
			new_mapping->remote_ip     = saddr;
			new_mapping->remote_port   = sport;
			new_mapping->internal_ip   = rule_entry->internal_ip;
			new_mapping->internal_port = rule_entry->internal_port;
			new_mapping->external_ip   = rule_entry->external_ip;
			new_mapping->external_port = rule_entry->external_port;
			new_mapping->update_time   = 0;
			memset(&new_mapping->conn,0,sizeof(struct nat_connection));
			list_add_tail(&new_mapping->list, &mapping_entry->list);
			mapping_entry = new_mapping;
		}
	}
	else
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);

	update_send_packet(packet, mapping_entry, len, dir);

	pthread_mutex_unlock(&nat.lock);
	return;
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	int i = 0;
	while (1) {
		//fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
        pthread_mutex_lock(&nat.lock);

        for (i = 0; i < HASH_8BITS; i++) {
			struct list_head *head = &nat.nat_mapping_list[i];
			struct nat_mapping *mapping_entry, *q;
			list_for_each_entry_safe(mapping_entry, q, head, list) {
				mapping_entry->update_time ++;
				if(is_flow_finished(&mapping_entry->conn) || mapping_entry->update_time >= TCP_ESTABLISHED_TIMEOUT)
					list_delete_entry(&mapping_entry->list);
			}
		}

		pthread_mutex_unlock(&nat.lock);
	}
	return NULL;
}

#define MAX_STR_SIZE 100
int get_next_line(FILE *input, char (*strs)[MAX_STR_SIZE], int *num_strings)
{
	const char *delim = " \t\n";
	char buffer[120];
	int ret = 0;
	if (fgets(buffer, sizeof(buffer), input)) {
		char *token = strtok(buffer, delim);
		*num_strings = 0;
		while (token) {
			strcpy(strs[(*num_strings)++], token);
			token = strtok(NULL, delim);
		}

		ret = 1;
	}

	return ret;
}

int read_ip_port(const char *str, u32 *ip, u16 *port)
{
	int i1, i2, i3, i4;
	int ret = sscanf(str, "%d.%d.%d.%d:%hu", &i1, &i2, &i3, &i4, port);
	if (ret != 5) {
		log(ERROR, "parse ip-port string error: %s.", str);
		exit(1);
	}

	*ip = (i1 << 24) | (i2 << 16) | (i3 << 8) | i4;

	return 0;
}

int parse_config(const char *filename)
{
	FILE *input;
	char strings[10][MAX_STR_SIZE];
	int num_strings;

	input = fopen(filename, "r");
	if (input) {
		while (get_next_line(input, strings, &num_strings)) {
			if (num_strings == 0)
				continue;

			if (strcmp(strings[0], "internal-iface:") == 0)
				nat.internal_iface = if_name_to_iface(strings[1]/*"n1-eth0"*/);
			else if (strcmp(strings[0], "external-iface:") == 0)
				nat.external_iface = if_name_to_iface(strings[1]/*"n1-eth1"*/);
			else if (strcmp(strings[0], "dnat-rules:") == 0) {
				struct dnat_rule *rule = (struct dnat_rule*)malloc(sizeof(struct dnat_rule));
				read_ip_port(strings[1], &rule->external_ip, &rule->external_port);
				read_ip_port(strings[3], &rule->internal_ip, &rule->internal_port);
				
				list_add_tail(&rule->list, &nat.rules);
			}
			else {
				log(ERROR, "incorrect config file, exit.");
				exit(1);
			}
		}

		fclose(input);
	}
	else {
		log(ERROR, "could not find config file '%s', exit.", filename);
		exit(1);
	}
	
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	//fprintf(stdout, "TODO: release all resources allocated.\n");
	int i = 0;
	pthread_mutex_lock(&nat.lock);

	for (i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *p, *q;
		list_for_each_entry_safe(p, q, head, list) {
			list_delete_entry(&p->list);
			free(p);
		}
	}
	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
	return;
}
