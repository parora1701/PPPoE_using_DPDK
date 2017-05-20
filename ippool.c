unsigned int net_range = 20;
unsigned int max_host = 0;
static unsigned int ip_count = 0;
static uint8_t count_oct3 = 0;
static uint8_t count_oct4 = 0;


//get dns values
PPPIpcpUsed * get_ip_dns(int session_index) {

	PPPIpcpUsed * ipDns;
	ipDns->ip = (session_array[session_index])->client_ipv4_addr;
	//ipDns->dns1 = 0x08080808; //C0A80001
	ipDns->dns1 = 0x0100a8c0; 
	ipDns->dns2 = 0x0100a8c0;
	return ipDns;
}


//get an ip from the ip pool
uint32_t get_ip() {

	unsigned int host_range = 32-net_range;
	//for safety ignoring 4 ip's 
	max_host = (1 << host_range)-4;
	uint32_t ip = 0;
	uint8_t oct1 = 0;
	uint8_t oct2 = 0;
	uint8_t oct3 = 0;
	uint8_t oct4 = 0;
	int error = 0;
	
	if (host_range <= 8) {
		if ((ip_count < max_host) && (count_oct4 < 254)) {
			count_oct4 += 1;
			oct4 = count_oct4;
			ip_count++;
		} else {
			error = 1;
		}

	} else if (host_range <= 16) {

		if ((ip_count < max_host) && (count_oct3 < 254)) {
			if ((ip_count < max_host) && (count_oct4 < 254)) {
				count_oct4 += 1;
				oct4 = count_oct4;
				ip_count++;
			} else if ((ip_count < max_host) && (count_oct4 = 254)) {
				count_oct4 = 1;
				count_oct3 += 1;
				oct4 = count_oct4;
				oct3 = count_oct3;
				ip_count++;
			}

		} else if ((ip_count < max_host) && (count_oct3 = 254)) {
			if ((ip_count < max_host) && (count_oct4 < 254)) {
				count_oct4 += 1;
				oct4 = count_oct4;
				ip_count++;
			} else if ((ip_count < max_host) && (count_oct4 = 254)) {
				error = 1;
			}
		} else {
			error = 1;
		}
	}
	oct1 = 192;
	oct2 = 168;

	if (error) {
		oct1 = 0;
		oct2 = 0;
		oct3 = 0;
		oct4 = 0;
	}

	ip = oct1 | (oct2 << 8) | (oct3 << 16) | (oct4 << 24);
	//printf("%d.%d.%d.%d.....%x\n", oct1, oct2, oct3, oct4, ip);

	return ip;	
}


//get the server's intranet ip
uint32_t get_server_ip() {

	uint32_t ip = 0x0500000a;
	return ip;
}
