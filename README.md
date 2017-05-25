PPPoE using DPDK


Pre-requisite: 

Steps: 
1) In pppoe.conf file add IP range that you want to allocate to PPPoE client under parameter "router_ip_addr_start" , "router_ip_addr_end" For example: 
#IPV4 address start range for gateway router
router_ip_addr_start=192.168.100.1
#IPV4 address end range for gateway router
router_ip_addr_end=192.168.101.100

2) Manually Add PPPoE servers MAC address as IPV4 route for all allocated IP address in gateway. For example in Windows command to add IPV4 route is : 

route add "IP_Address" mask "Mask" "Gateway IP address" if "Interface id"  (like this : route add 192.168.100.1 mask 255.255.255.255 192.168.56.1 if 0x8)

3) Add static ARP entry in the gateway for  PPPoE server. for windows command is : 
netsh interface ip add neighbors "Interface name" "IP address of PPPoE server interface facing gateway" "MAC address of PPPoE server"

4) run the make command after navigating to the server directory.

5) Do sudo ./configure-before-run.sh to check availability of enough Huge Pages.

6) Do sudo ./run.sh (Make sure DPDK directory specified in run.sh file is correct) to start PPPoE server. 

7) Make DSL connection from PPPoE client which is on same intranet as PPPoE server.

