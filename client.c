#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "functions_cli.h"
#define MAX_MSG_LEN 50


struct ip_stats {
	struct in_addr ip_addr;
	uint64_t num;
//	struct ip_stats *next;
};

int main (int argc, char ** argv) {

	int ev_sock = -1;
	struct sockaddr_un ev_sock_struct;
	char buf[50] = {0};
	
	/* pid_t pid = fork(); */

	/* if (pid == 0) { */
	/*     execl ("./sniffer", "sniffer", argv[1], NULL); */
	/* } */
	/* else if (pid > 0) { */
	/*     printf("Child PID is %d\n", (int)pid); */
	/* } */
	/* else { */
	/*     perror("fork failed"); */
	/* } */

	sleep(3);
	ev_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (ev_sock < 0) {
		printf ("ERROR!\n");
		return 1;
	}

	ev_sock_struct.sun_family = AF_UNIX;
	strcpy(ev_sock_struct.sun_path, "ev_sock_file");

	if (connect(ev_sock, (struct sockaddr *) &ev_sock_struct, sizeof(ev_sock_struct)) < 0) {
		printf ("ERROR! Error connecting socket! \n");
		close(ev_sock);
		return 1;
	}

	while (1) {
		memset(buf, 0, sizeof(buf));

		fgets(buf, MAX_MSG_LEN, stdin);
		buf[strlen(buf) - 1] = '\0';
		if (!strcmp(buf, "--help")) {
			f_usage(argv[0]);
			continue;
		} else {
	
			write(ev_sock, buf, strlen(buf));

			if ((strstr(buf, "show") != NULL) && (strstr(buf, "count")) != NULL) {
				char ip[16];
				char buff[255];

				memset(buff, 0, sizeof(buff));
			}
		}

	}

	return 0;
}

