#define IPV4_OPTIONS(HEADER_SIZE, OPTIONS) ((HEADER_SIZE > 5) ? (OPTIONS) : 0)
#define IP_HASH(x) ((((x / 256) / 256) / 256) % 256) ^ (((x / 256) / 256) % 256) ^  ((x / 256) % 256) ^ (x % 256) 
#define MAX_IP_NUM 1000

struct ether_header {
	unsigned char dest_mac [6];
	unsigned char src_mac [6];
	unsigned short eth_type;
} __attribute__((__packed__));

struct ipv4_header {
	unsigned char version_header_size; 			/* 4 bits for version, 4 bits for header size */
	unsigned char dscp_ecn;  		   			/* 4 bits for DSCP, 4 bits for ECN */
	unsigned short packet_size; 
	unsigned short identificator;
	unsigned short flags_fragment_offset;		/* 3 bits for flags, 13 bits for fragment offset */
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned int ip_source;
	unsigned int ip_dest;
	unsigned int options;
}__attribute__((__packed__)); 


struct types_array {
	unsigned short type;
	char * string;
};

struct thread_data {
	int sock;
};

struct ip_stats {
	struct in_addr ip_addr;
	uint64_t num;
//	struct ip_stats *next;
};

int f_usage (char* program_name); 
void mac_level_output (struct ether_header * data_packet);
void ip_level_output (struct ipv4_header * data_ipv4);
int start_capture(int sock, const char *ifname); 
int init_capture();
int deinit_capture(int sock);
int init_conn (); 
int stop_capture(int sock); 
void print_ip_stats (struct ip_stats stats); 
struct ip_stats stats_data (struct ip_stats stats, struct in_addr ip_source_struct);
void * main_sniffer_func (void * param);
int ret_index_by_name (char * device_name, struct ifreq iface, int sock);
void string_parsing (char * buff, int ev_sock, int sock); 
