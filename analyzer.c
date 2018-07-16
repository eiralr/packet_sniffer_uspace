#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h> 
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include "analyzer.h"

#define MAX_MSG_LEN 50


int main(int argc, char **argv) {

	int sock = -1;
	int ev_sock = -1;
	char iface[10];
	char buff [MAX_MSG_LEN] = {0};
	struct sockaddr_un ev_sock_struct;
	struct in_addr ip_recv;


	sock = init_capture();

	ev_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ev_sock < 0) {
		printf ("ERROR!\n");
		return 1;
	}

	ev_sock_struct.sun_family = AF_UNIX;
	strcpy(ev_sock_struct.sun_path, "ev_sock_file");
	
	unlink("ev_sock_file");

	if (bind(ev_sock, (struct sockaddr *) &ev_sock_struct, sizeof(ev_sock_struct)) < 0) {
		printf ("ERROR! Error binding socket! \n");
		close(ev_sock);
		return 1;
	}

	
	while(1) {
		if (recvfrom(ev_sock, buff, sizeof(buff), 0, NULL, 0) == -1) {
			printf ("ERROR! In recvfrom() func \n");
			return 0;
		}

printf ("=======> %s \n", buff);

		if (!strcmp("start", buff)) {
			start_capture(sock, NULL);
		} else if (!strcmp("stop", buff)) {
			stop_capture(sock);
		} else if (strstr(buff, "select iface") != NULL) {
			strcpy(iface, buff + strlen("select iface "));
			iface[strlen(iface) - 1] = '\0';
			start_capture(sock, iface);
		} else if (!strcmp("quit", buff)) {
			printf("%s stoped!", argv[0]);
			exit(0);
		} else if ((strstr(buff, "show") != NULL) && (strstr(buff, "count")) != NULL) {
			char ip[16];
			if (sscanf (buff, "show %s", ip) != 0) {
				struct in_addr inp;
				if(inet_aton(ip, &inp) == 0) {
					printf ("Wrong ip address format!");
				} else {
					IP_HASH(inp.s_addr);	
					
				}
			}
		}

 
		memset(buff, 0, sizeof(buff));
	}

	deinit_capture(sock);

	return 0;
}
