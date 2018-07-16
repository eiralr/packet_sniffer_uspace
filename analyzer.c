#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
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
	char buff [MAX_MSG_LEN] = {0};
	struct thread_data param;
	
	param.sock = init_capture();
	ev_sock = init_conn();

	while(1) {
		if (recvfrom(ev_sock, buff, sizeof(buff), 0, NULL, 0) == -1) {
			printf ("ERROR! In recvfrom() func \n");
			return 0;
		}
		string_parsing (buff, ev_sock, param.sock);	
	}

	deinit_capture(sock);

	return 0;
}
