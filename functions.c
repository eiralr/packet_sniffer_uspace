#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include "analyzer.h"

#define MAC_ADDR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ADDR_STR(x) x[0], x[1], x[2], x[3], x[4], x[5]
#define ARR_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
 
static int capture_started = 0;
struct ether_header * data_packet; 
struct ipv4_header * data_ipv4;
struct tcp_header * data_tcp;
struct in_addr ip_source_struct;
struct in_addr ip_dest_struct;

static struct ip_stats *hash_table[256];

/*struct ip_stats */ void ip_search (int num) {
	printf("IP ADDRESS: %s\n", inet_ntoa(hash_table[num]->ip_addr));
	printf("PACKET NUMS %lu\n", hash_table[num]->num);
}


int init_capture() {
	int sock = -1;

	if ((sock = socket (AF_PACKET, SOCK_RAW, ETH_P_ALL)) < 0) {
		printf("-->ERROR! %s\n", strerror(errno));	
		return 1;	
	}
	return sock;
}

int deinit_capture(int sock) {
	close(sock);
	return 0;
}

void mac_level_output (struct ether_header * data_packet) {
		int i = 0;


	struct types_array table_of_types_ll [] = {
		{0x0800, "IPv4"},
		{0x0806, "ARP"},
		{0x8137, "IPX"},
		{0x888E, "EAP"},
	};

		printf ("Destination MAC: " MAC_ADDR_FMT "\n", MAC_ADDR_STR(data_packet->dest_mac));	
		printf ("Source MAC: " MAC_ADDR_FMT "\n", MAC_ADDR_STR(data_packet->src_mac));

		for (i = 0; i < ARR_SIZE(table_of_types_ll); i++) {
			if (table_of_types_ll[i].type ==  ntohs(data_packet->eth_type)) {
				printf ("EtherType: %#.4x is %s\n \n", ntohs(data_packet->eth_type), table_of_types_ll[i].string);
				break;
			}
		}
}

void ip_level_output (struct ipv4_header * data_ipv4) {
	int i = 0;


	struct types_array table_of_types_ipl [] = {
		{6, "TCP"},
		{17, "UDP"},
		{40, "IL Protocol"},
		{47, "Generic Routing Encapsulation"},
		{50, "Encapsulating Security Payload"},
		{51, "Authentication Header"},
		{132, "Stream Control Transmission Protocol"},
	};



	printf ("Version: %hhu \n", (data_ipv4->version_header_size >> 4));
	printf ("Header size: %hhu \n", (data_ipv4->version_header_size & 0xF));
	printf ("DCSP: %u \n", (data_ipv4->dscp_ecn >> 2));
	printf ("ECN: %u \n", (data_ipv4->dscp_ecn & 3));
	printf ("Packet size: %hu \n", ntohs(data_ipv4->packet_size));
	printf ("Identificator: %hu \n", ntohs(data_ipv4->identificator));
	printf ("Flags: %u \n", ntohs(data_ipv4->flags_fragment_offset) >> 13);
	printf ("Fragment offset: %u \n", ntohs(data_ipv4->flags_fragment_offset) & 0x1FFF);
	printf ("Time to live: %hhu \n", data_ipv4->time_to_live);


	for (i = 0; i < ARR_SIZE(table_of_types_ipl); i++) {
		if (table_of_types_ipl[i].type == data_ipv4->protocol) {	
			printf ("Protocol: %hhu is %s \n", data_ipv4->protocol, table_of_types_ipl[i].string);
			break;
		}
	}

//	ip_source_struct.s_addr = data_ipv4->ip_source;
	ip_dest_struct.s_addr = data_ipv4->ip_dest;


	printf ("Header checksum: %hu \n", ntohs(data_ipv4->header_checksum));
	printf ("Source IP address: %s \n", inet_ntoa (ip_source_struct));
	printf ("Destination IP address: %s \n", inet_ntoa(ip_dest_struct));
	printf ("Options: %x \n", IPV4_OPTIONS ((data_ipv4->version_header_size & 0xF), ntohl(data_ipv4->options)));
}

void tcp_level_output (struct tcp_header * data_tcp) {

	printf ("Source port: %hu \n", ntohs (data_tcp->source_port));
	printf ("Destination port: %hu \n", ntohs (data_tcp->dest_port));

	if (data_ipv4->protocol == 6) {

		printf ("Sequence number: %u \n", ntohl (data_tcp->seq_num));
		printf ("Acknoulegement number: %u \n", ntohl (data_tcp->ack_num));
		printf ("Data offset: %hhu \n", (data_tcp->data_offset_reserved >> 4));
		printf ("Reserved: %hhu \n", data_tcp->data_offset_reserved & 0xF);
		printf ("TCP layer flags: %u \n", data_tcp->tcp_flags);
		printf ("Window size: %u \n", ntohs(data_tcp->win_size));
		printf ("Checksum: %hu \n", ntohs (data_tcp->checksum));
		printf ("Urgent pointer: %hu \n", ntohs(data_tcp->urg_pointer));
		printf ("Options: %u \n", ntohs(data_tcp->options));
	}

}

int main_sniffer_func(int sock) {

	int i = 0;
	char *buff = NULL;
	ssize_t rec = 0;

	struct types_array table_of_types_ipl [] = {
		{6, "TCP"},
		{17, "UDP"},
		{40, "IL Protocol"},
		{47, "Generic Routing Encapsulation"},
		{50, "Encapsulating Security Payload"},
		{51, "Authentication Header"},
		{132, "Stream Control Transmission Protocol"},
	}; 

	buff = (char *) malloc (ETH_FRAME_LEN);
	if (!buff) {
		printf("Failed to allocate memory!\n");
		return 1;
	}

	while (capture_started) {

		int num = 0;
	
		rec = recvfrom (sock, buff, ETH_FRAME_LEN, 0, NULL, 0);
		if (rec == -1)
			return 1;

		data_packet = (struct ether_header *) buff;

		printf ("Packet size: %ld \n", rec);

		mac_level_output(data_packet);

		if (ntohs(data_packet->eth_type) == 0x0800) {

			data_ipv4 = (struct ipv4_header *) &buff[sizeof(struct ether_header)];

			num = IP_HASH(data_ipv4->ip_source);
			ip_source_struct.s_addr = data_ipv4->ip_source;
			hash_table[num]->ip_addr = ip_source_struct;
			hash_table[num]->num++;

			ip_level_output(data_ipv4);
		} 

		printf ("\n \n");
	}

	free (buff); 

	return 0;
}


int ret_index_by_name (char * device_name, struct ifreq iface, int sock) {

		strncpy((char *)iface.ifr_name, device_name, IFNAMSIZ);
		if ((ioctl(sock, SIOCGIFINDEX, &iface)) == -1) {
			printf("Error getting Interface index !\n");
			return -1;
		}

		printf ("%d\n\n", iface.ifr_ifindex);
		return iface.ifr_ifindex;	
}


int start_capture(int sock, const char *ifname) {

	struct ifreq iface;
	struct ifaddrs *iface_list;
	struct ifaddrs *ifc;
	struct sockaddr_ll sll;
	pthread_t capt_thread;

	if (getifaddrs(&iface_list) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}


	for (ifc = iface_list; (ifc->ifa_next) != NULL; ifc = ifc->ifa_next) {
		if (ifc->ifa_addr->sa_family == PF_PACKET) { 
			if (ifc->ifa_flags & IFF_UP) {  
				if (!ifname) {
					sll.sll_ifindex = ret_index_by_name(ifc->ifa_name, iface, sock);
					printf("Default iface selected: %-8s \n", ifc->ifa_name); 
				} else {
					if(!strcmp(ifc->ifa_name, ifname)) {
						printf("Capture started on iface %-8s \n", ifc->ifa_name); 
						sll.sll_ifindex = ret_index_by_name(ifc->ifa_name, iface, sock);
						break;
					} else
						continue;
				}
			}
		}
	}



	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(sock, (struct sockaddr *) &sll, sizeof (sll)) == -1) {
		printf ("ERROR! %s\n", strerror(errno));
		return 1;
	}

	capture_started = 1;

	if (pthread_create(&capt_thread, NULL, (void *) (&main_sniffer_func), NULL) != 0) {
		printf ("ERROR! Can't create thread! \n");
	}
		
	main_sniffer_func(sock);
}

/* mktemp	 */

int stop_capture(int sock) {
	capture_started = 0;
	/* thread stop */
}
