#include "include/queue.h"
#include "include/skel.h"

// function to build an arp packet and send it
void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t arp_op) {
	struct arp_header *arphdr = malloc(sizeof(struct arp_header));
	memcpy(arphdr->sha, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(arphdr->tha, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	arphdr->spa = saddr;
	arphdr->tpa = daddr;
	arphdr->htype = htons(ARPHRD_ETHER);
	arphdr->ptype = htons(2048);
	arphdr->op = arp_op;
	arphdr->hlen = 6;
	arphdr->plen = 4;

	packet *packet = malloc(sizeof packet);
	memset(packet->payload, 0, 1600);
	memcpy(packet->payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet->payload + sizeof(struct ethhdr), arphdr, sizeof(struct arp_header));
	packet->len = sizeof(struct arp_header) + sizeof(struct ethhdr);
	packet->interface = interface;
	send_packet(packet);
}

// function to build and send icmp packet
void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, int interface) {
	struct ether_header eth_hdr;
	memcpy((&eth_hdr)->ether_dhost, dha, ETH_ALEN);
	memcpy((&eth_hdr)->ether_shost, sha, ETH_ALEN);
	(&eth_hdr)->ether_type = htons(ETHERTYPE_IP);

	struct iphdr ip_hdr;
	(&ip_hdr)->version = 4;
	(&ip_hdr)->ihl = 5;
	(&ip_hdr)->tos = 0;
	(&ip_hdr)->protocol = IPPROTO_ICMP;
	(&ip_hdr)->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	(&ip_hdr)->id = htons(1);
	(&ip_hdr)->frag_off = 0;
	(&ip_hdr)->ttl = 64;
	(&ip_hdr)->check = 0;
	(&ip_hdr)->daddr = daddr;
	(&ip_hdr)->saddr = saddr;
	(&ip_hdr)->check = ip_checksum((void *)(&ip_hdr), sizeof(struct iphdr));

	struct icmphdr icmp_hdr;
	(&icmp_hdr)->type = type;
	(&icmp_hdr)->code = 0;
	(&icmp_hdr)->checksum = 0;
	(&icmp_hdr)->un.echo.id = 0;
	(&icmp_hdr)->un.echo.sequence = 0;
	(&icmp_hdr)->checksum = icmp_checksum((void *)(&icmp_hdr), sizeof(struct icmphdr));

	packet packet;
	void *payload;

	payload = packet.payload;
	memcpy(payload, (&eth_hdr), sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, (&ip_hdr), sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, (&icmp_hdr), sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	packet.interface = interface;

	send_packet(&packet);
}

// get matching ip from arp table
struct arp_entry* get_arp_entry(uint32_t dest_ip, struct arp_entry* arptable, int arptable_length) {
	for (int i = 0; i < arptable_length; i++) {
		if(arptable[i].ip == dest_ip)
			return &arptable[i];
	}
	return NULL;
}

// comparator for C qsort
int comparator(const void* p1, const void* p2) {
	struct route_table_entry* v1 = (struct route_table_entry*) p1;
	struct route_table_entry* v2 = (struct route_table_entry*) p2;

	if(v1->prefix > v2->prefix)
		return 1;
	else if(v1->prefix == v2->prefix) {
		if(v1->mask > v2->mask)
			return 1;
	}

	return -1;
}

// binary search + partial linear search for LPM
struct route_table_entry *get_best_route(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_len) {
	struct route_table_entry *res = NULL;
	int best = 0;
	int left = 0;
	int right = rtable_len - 1;
	while(left <= right) {
		int mid = (left + right)/2;
		if((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
			best = mid;
			left = mid + 1;
		}
		if((rtable[mid].mask & dest_ip) > rtable[mid].prefix)
			left = mid + 1;
		else
			right = mid - 1;
	}

	for(int i = best; i < rtable_len; i++) {
		if((dest_ip & rtable[i].mask) == rtable[i].prefix && (res == NULL || (res->mask < rtable[i].mask)))
			res = &rtable[i];
	}

	return res;
}

// incremental checksum bonus
void ip_checksum_bonus(struct iphdr *ip_hdr) {
	uint8_t old_value = ip_hdr->ttl;
	ip_hdr->ttl--;
	uint8_t new_value = ip_hdr->ttl;
	ip_hdr->check =  ip_hdr->check - (~old_value) - new_value - 1;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry)*100000);
	int rtable_length = read_rtable(argv[1], rtable);
	struct arp_entry *arptable = (struct arp_entry *)malloc(sizeof(struct arp_entry)*100000);
	int arptable_length = 0;
	queue q = queue_create();
	qsort(rtable, rtable_length, sizeof(struct route_table_entry), comparator);
	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header)); 
		struct arp_header *arphdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

		// IPV4 packet
		if(eth_hdr->ether_type == htons(ETHERTYPE_IP)){
			// ICMP over the IPV4
			if(ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct iphdr) + sizeof(struct ether_header));
				if(icmp_hdr != NULL && icmp_hdr->type == ICMP_ECHO && ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, m.interface);
					continue;
				}
			}

			// validate checksum
			uint16_t sum_before = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t sum_check = ip_checksum((void *)ip_hdr, sizeof(struct iphdr));
			ip_hdr->check = sum_before;
			if(sum_before != sum_check)
				continue;

			// validate ttl
			if(ip_hdr->ttl <= 1) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, m.interface);
				continue;
			}
			else
			// update checksum and ttl
				ip_checksum_bonus(ip_hdr);		

			// check if there is an entry for the received ip 
			struct route_table_entry *best = get_best_route(ip_hdr->daddr, rtable, rtable_length);
			if(best == NULL){
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_DEST_UNREACH, m.interface);
				continue;
			}

			// get next hop
			struct arp_entry *next = get_arp_entry(ip_hdr->daddr, arptable, arptable_length);

			if(next == NULL) {
				// save until it receives the mac address
				packet* saved = malloc(sizeof(m));
				memcpy(saved, &m, sizeof(m));
				queue_enq(q, saved);

				struct ether_header *aux_eth_hdr = malloc(sizeof(struct ether_header));
				aux_eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(best->interface, aux_eth_hdr->ether_shost);
				hwaddr_aton("ff:ff:ff:ff:ff:ff", aux_eth_hdr->ether_dhost);
				send_arp(best->next_hop, inet_addr(get_interface_ip(best->interface)), aux_eth_hdr, best->interface, htons(ARPOP_REQUEST));
			} else {
				// send to destination
				get_interface_mac(best->interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, next->mac, sizeof(next->mac));
				m.interface = best->interface;
				send_packet(&m);
			}
		}
		// ARP packet
		else if(eth_hdr->ether_type == htons(ETHERTYPE_ARP)){
			// ARP REQUEST of router's mac address
			if (arphdr->op == htons(ARPOP_REQUEST) && arphdr->tpa == inet_addr(get_interface_ip(m.interface))) {
				struct ether_header *aux_eth_hdr = malloc(sizeof(struct ether_header));
				aux_eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				get_interface_mac(m.interface, aux_eth_hdr->ether_shost);
				memcpy(aux_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				send_arp(arphdr->spa, arphdr->tpa, aux_eth_hdr, m.interface, htons(ARPOP_REPLY));
			// ARP REPLY after finding mac address	
			} else if (arphdr->op == htons(ARPOP_REPLY)) {
				struct arp_entry arp_reply;
				queue aux_q = queue_create();
				arp_reply.ip = arphdr->spa;
				memcpy(arp_reply.mac, arphdr->sha, sizeof(arphdr->sha));
				arptable[arptable_length] = arp_reply;
				arptable_length++;

				while(!queue_empty(q)){
					packet* aux = (packet*)queue_deq(q);
					struct iphdr* aux_ip_hdr = (struct iphdr*)(aux->payload + sizeof(struct ether_header));
					struct route_table_entry *best = get_best_route(aux_ip_hdr->daddr, rtable, rtable_length);

					if(best->next_hop == arphdr->spa) {
						struct ether_header *aux_eth_hdr = (struct ether_header *)aux->payload;
						memcpy(aux_eth_hdr->ether_dhost, arphdr->sha, sizeof(arphdr->sha));
						get_interface_mac(best->interface, aux_eth_hdr->ether_shost);
						aux->interface = best->interface;
						send_packet(aux);
					}
					else 
						queue_enq(aux_q, aux);
				}
				q = aux_q;
			}
		}
	}
}