#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "functions_cli.h"
#define MAX_MSG_LEN 50

int main (int argc, char ** argv) {

	int ev_sock = -1;
	struct sockaddr_un ev_sock_struct;
	char buf[50] = {0};
	
	pid_t pid = fork();

	if (pid == 0) {
		execl ("./sniffer", "sniffer", argv[1], NULL);
	}
	else if (pid > 0) {
		printf("Child PID is %d\n", (int)pid);
	}
	else {
		perror("fork failed");
	}

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
		fgets(buf, MAX_MSG_LEN, stdin);
		if (!strcmp(buf, "--help")) {
			f_usage(argv[0]);
			continue;
		}
		write(ev_sock, buf, strlen(buf));
	}



	return 0;
}

