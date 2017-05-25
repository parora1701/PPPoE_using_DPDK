/* pppoe - Contains declarations of all structures used.
 * Copyright (C) 2016  Govind Singh
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * govind.singh@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

/***********************************************************
 *User configurable parameters
 *Populated from pppoe.conf file
 ***********************************************************/

//service name
unsigned char * service_name;

//AC name
unsigned char * ac_name;

//debug option
unsigned int DEBUG;

//Authentication protocol, 0 for PAP, 1 for CHAP (currently PAP only)
unsigned int auth_proto;

//mac addresses
struct ether_addr srtointra_addr;
struct ether_addr srtointer_addr;
struct ether_addr gateway_addr;

//IPV4 address pool with classless subnet mask, need only range
unsigned int net_range;

//ip addresses
uint32_t ip_intra;
uint32_t ip_inter;
uint32_t ip_gateway;

//primary dns
uint32_t ip_dns1;

//secondary dns
uint32_t ip_dns2;

//session and connection idle timeout  (in minute)
double sess_timeout;
//this is a stale entry (ignore it)
double conn_timeout;

//start and end ranges
uint8_t start_ip_oct1;
uint8_t start_ip_oct2;
uint8_t start_ip_oct3;
uint8_t start_ip_oct4;
uint8_t end_ip_oct3;
uint8_t end_ip_oct4;

/***********************************************************
 *Server specific declarations
 *Do not modify any structures
 ***********************************************************/
#include<pthread.h>
#include<time.h>
#include<math.h>

//Ring global variable declaration.
static uint8_t pppoe_enabled_ports[RTE_MAX_ETHPORTS];
#define RING_SIZE 1024
#define MAX_STR_LEN 100
#define MAC_LEN 6
#define IP_LEN 4

typedef struct ConfigParam
{
    char serviceName[MAX_STR_LEN];
    char acName[MAX_STR_LEN];
    int isDebug;
    int authProtocol;
    unsigned char servToIntraMac[MAC_LEN];
    unsigned char servToInterMac[MAC_LEN];
    unsigned char routerMac[MAC_LEN];
    unsigned char servToIntraIP[IP_LEN];
    unsigned char servToInterIP[IP_LEN];
    unsigned char routerIP[IP_LEN];
    unsigned char ipAddressPool[5];
    unsigned char primaryDns[IP_LEN];
    unsigned char secondaryDns[IP_LEN];
    double sessionTimeout;
    double connectionTimeout;
    unsigned char routerIpStart[IP_LEN];
    unsigned char routerIpEnd[IP_LEN];
} ConfigParameter;

ConfigParameter * getConfigParameters();

extern struct rte_mempool* mempool;
extern pthread_mutex_t conn_lock;

#define BURSTLEN	4
#define ETH_JUMBO_LEN	20

//protocols
#define PROTO_TCP 	0x06
#define PROTO_UDP 	0x11

//ETHER_TYPE fields
#define ETHER_DISCOVERY	0x8863
#define ETHER_SESSION	0x8864
#define ETHER_IPV4	0x0800

//PPPoE version and type
#define PPPOE_VER	0x01
#define PPPOE_TYPE	0x01

//PPPoE codes
#define CODE_PADI	0x09
#define CODE_PADO	0x07
#define CODE_PADR	0x19
#define CODE_PADS	0x65
#define CODE_PADT	0xa7
#define CODE_SESS	0x00

//PPPoE encapsulation structure
typedef struct
__attribute__((__packed__))
{
    struct ether_hdr l2hdr;
    unsigned int type :4;
    unsigned int ver :4;
    unsigned int code :8;
    unsigned int session :16;
    unsigned int length :16;
}
PPPoEEncap;

//PPPoE tag types
#define TYPE_END_OF_LIST 	0x0000
#define TYPE_SERVICE_NAME 	0x0101
#define TYPE_AC_NAME		0x0102
#define	TYPE_HOST_UNIQ		0x0103
#define TYPE_AC_COOKIE		0x0104
#define	TYPE_VENDOR_SPECIFIC 	0x0105
#define TYPE_RELAY_SESSION_ID 	0x0110
#define TYPE_SERVICE_NAME_ERROR	0x0201
#define TYPE_AC_SYSTEM_ERROR	0x0202
#define TYPE_GENERIC_ERROR	0x0203

//PPPoE tag structure
typedef struct
__attribute__((__packed__))
{
    unsigned int type :16;
    unsigned int length :16;
}
PPPoETag;

//PPP protocols
#define PROTO_LCP	0xc021
#define	PROTO_PAP	0xc023
#define	PROTO_LQR	0xc025
#define	PROTO_CHAP	0xc223
#define	PROTO_CCP	0x80fd
#define	PROTO_IPCP	0x8021
#define PROTO_IPV6C 	0x8057
#define PROTO_IPV4	0x0021

//PPP eccapsulation structure
typedef struct
__attribute__((__packed__))
{
    unsigned int protocol :16;
}
PPPEncap;

//PPP lcp codes
#define CODE_CONF_REQ	0x01
#define CODE_CONF_ACK	0x02
#define CODE_CONF_NAK	0x03
#define CODE_CONF_REJ	0x04
#define CODE_TERM_REQ	0x05
#define CODE_TERM_ACK	0x06
#define CODE_CODE_REJ	0x07
#define CODE_PROT_REJ	0x08
#define CODE_ECHO_REQ	0x09
#define CODE_ECHO_REP	0x0a
#define CODE_DISC_REQ	0x0b

//PPP LCP structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
}
PPPLcp;

//PPP LCP Echo structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
    unsigned int magic_number :32;
}
PPPLcpMagic;

//PPP LCP reject structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
    unsigned int protocol :16;
}
PPPLcpRjct;

//PPP LCP option types
#define TYPE_MRU	0x01
#define TYPE_AUP	0x03
#define TYPE_QUP	0x04
#define TYPE_MGN	0x05
#define TYPE_PFC	0x07
#define TYPE_ACC	0x08

//PPP LCP options
typedef struct
__attribute__((__packed__))
{
    unsigned int type :8;
    unsigned int length :8;
}
PPPLcpOptions;

//PPP LCP options general structure
typedef struct
__attribute__((__packed__))
{
    unsigned int type :8;
    unsigned int length :8;
    unsigned int value :16;
}
PPPLcpOptionsGenl;

//PPP LCP options magic structure
typedef struct
__attribute__((__packed__))
{
    unsigned int type :8;
    unsigned int length :8;
    unsigned int value :32;
}
PPPLcpOptionsMagic;

//PPP PAP codes
#define CODE_AUT_REQ	0x01
#define CODE_AUT_ACK	0x02
#define CODE_AUT_NAK	0x03

//PPP PAP REQ structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
}
PPPPapReq;

//PPP PAP ACK structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
    unsigned int idms_length :8;
}
PPPPapAck;

//PPP IPCP codes
#define CODE_IPCP_REQ	0x01
#define CODE_IPCP_ACK	0x02
#define CODE_IPCP_NAK	0x03

//PPP IPCP structure
typedef struct
__attribute__((__packed__))
{
    unsigned int code :8;
    unsigned int identifier :8;
    unsigned int length :16;
}
PPPIpcp;

//PPP IPCP options
#define TYPE_IP		0x03
#define TYPE_DNS_PRI	0x81
#define TYPE_DNS_SEC	0x83

//PPP IPCP options structure
typedef struct
__attribute__((__packed__))
{
    unsigned int type :8;
    unsigned int length :8;
    unsigned int value :32;
}
PPPIpcpOptions;

//PPP IPCP used values structure
typedef struct
__attribute__((__packed__))
{
    uint32_t ip;
    uint32_t dns1;
    uint32_t dns2;
}
PPPIpcpUsed;

//session states
#define STATE_SESS_CRTD		0x00
#define STATE_PADS_SENT		0x01
#define STATE_CONF_AUTH_SENT	0x02
#define	STATE_AUTH_ACK_SENT	0x03
#define STATE_AUTH_ECHO_SENT	0x04
#define STATE_TERM_SENT		0x05

//session structure
typedef struct
__attribute__((__packed__))
{
    unsigned int state :8;
    struct ether_addr client_mac_addr;
    uint32_t client_ipv4_addr;
    unsigned int session_id :16;
    char * host_uniq;
    uint16_t hu_len;
    unsigned int auth_ident :8;
    unsigned int echo_ident :8;
    unsigned int ip_ident :8;
    unsigned int mru;
    time_t time;
    uint8_t active;
}
Session;

extern Session ** session_array;
static int session_index = 0;

//functions
void send_config_req(
    uint8_t type,
    uint16_t session_index,
    struct ether_addr client_l2addr);
void send_echo_req(
    uint16_t session_index,
    struct ether_addr client_l2addr);
void send_auth_ack(
    uint8_t identifier,
    uint16_t session_index,
    struct ether_addr client_l2addr);
void send_auth_nak(
    uint8_t identifier,
    uint16_t session_index,
    struct ether_addr client_l2addr);
void send_proto_reject(
    uint16_t type,
    struct rte_mbuf * pkt);
PPPIpcpUsed * get_ip_dns(
    int session_index);
uint32_t get_ip();
uint32_t get_server_ip();
void send_ip_req(
    uint16_t session_index,
    struct rte_mbuf* pkt);
int ethaddr_to_string(
    char* str2write,
    const struct ether_addr* eth_addr);
int create_session(
    struct ether_addr client_l2addr);
int get_sslot();
int fill_session(
    int index,
    struct ether_addr client_l2addr);
void update_session(
    int index,
    struct ether_addr client_l2addr);
void delete_session(
    int index);
uint32_t check_and_set_ip();
void send_term_req(
    uint16_t index);
void send_padt(
    uint16_t s_index);
void * check_and_free_session();
int auth(
    char * username,
    char * password);
void read_config();
unsigned long long gettime();
