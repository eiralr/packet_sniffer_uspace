#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "functions_cli.h"


void f_usage (char* program_name) {
	printf ("USAGE: \n"
			"	sudo %s [start] [stop] [show [ip] count] [select iface [iface]] stat[iface] \n"
			"	start - packets are being sniffed from now on from default iface (eth0) \n"
			"	stop - packets are not sniffed \n "
			"	show [ip] count - print number of packets received from selected ip address \n "
			"	select_iface [iface] - select interface for sniffing eth0, wlan0, ethN, wlanN \n"
			"	stat [iface] - show all collected statistics for particular interface, if iface ommited - for all interfaces \n", program_name);
	exit (0);
}



