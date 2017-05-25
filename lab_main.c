/* lab_main - Starting point of server, establishes mempool and enables lcores and interfaces.
 * Copyright (C) 2016  Puneet Arora
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
 * puneet.arora@stud.tu-darmstadt.de, Technical University Darmstadt
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

//======= Pre-Definitions

//#define TEST_HASH_ONLY

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
#define MAX_SIZE_BURST 32
#define MEMPOOL_CACHE_SIZE 256

//======= Definitions

#define CACHE_LINE_SIZE		64
#define UINT8_UNDEF		255
#define RTE_MAX_IFACE		255

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define ETHDEV_ID	0

#include "pppoe.h"
#include "ippool.c"
#include "session.c"
#include "lab_task.c"
#include "pppoe_auth.c"
#include "pppoeconfig.c"

struct rte_mempool* mempool;
uint8_t pppoe_enabled_port_nb;

pthread_mutex_t conn_lock;

static struct rte_eth_conf default_ethconf = { .link_speed = 0,
           .link_duplex = 0, .rxmode = { .mq_mode = ETH_MQ_RX_NONE,
                                         .max_rx_pkt_len = 0, .split_hdr_size = 0, .header_split = 0,
                                         .hw_ip_checksum = 0, .hw_vlan_filter = 0, .hw_vlan_strip = 0,
                                         .hw_vlan_extend = 0, .jumbo_frame = 0, .hw_strip_crc = 0,
                                         .enable_scatter = 0, .enable_lro = 0,
                                       }, .txmode = { .mq_mode =
                                               ETH_MQ_TX_NONE, .hw_vlan_reject_tagged = 0,
                                                      .hw_vlan_reject_untagged = 0, .hw_vlan_insert_pvid = 0,
                                                    },
    .lpbk_mode = 0, .rx_adv_conf = { .rss_conf = {	//Receive Side Scaling.
            .rss_key = NULL, .rss_key_len = 0, .rss_hf = 0,
        },
    },
};

static const struct rte_eth_rxconf rx_conf = { .rx_thresh = { .pthresh = 8,	//prefetch
                                                                  .hthresh = 8,	//host
                                                                  .wthresh = 4	//write-back
                                                                }, .rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = { .tx_thresh = { .pthresh = 36,
                                                            .hthresh = 0, .wthresh = 0
                                                          }, .tx_free_thresh = 0, .tx_rs_thresh = 0,
                                                              .txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOVLANOFFL
                                                                      | ETH_TXQ_FLAGS_NOXSUMSCTP | ETH_TXQ_FLAGS_NOXSUMUDP
                                                                      | ETH_TXQ_FLAGS_NOXSUMTCP)

};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
    const uint16_t rx_rings = 1;
    const uint16_t tx_rings = 1;
    int retval;
    uint16_t q;

    if (port >= rte_eth_dev_count())
        return -1;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &default_ethconf);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, RTE_TEST_RX_DESC_DEFAULT,
                                        rte_eth_dev_socket_id(port), &rx_conf, mempool);

        if (retval < 0)
            return retval;
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {

        retval = rte_eth_tx_queue_setup(port, q, RTE_TEST_TX_DESC_DEFAULT,
                                        rte_eth_dev_socket_id(port), &tx_conf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable timesync timestamping for the Ethernet device */
    rte_eth_timesync_enable(port);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

static unsigned tz_getMBufMempoolSize(uint8_t ports_c, uint8_t lcores_c,
                                      uint8_t rx_queues_c, uint8_t tx_queues_c)
{

    unsigned result = ports_c * rx_queues_c * RTE_TEST_RX_DESC_DEFAULT
                      + ports_c * lcores_c * MAX_SIZE_BURST
                      + ports_c * tx_queues_c * RTE_TEST_TX_DESC_DEFAULT
                      + lcores_c * MEMPOOL_CACHE_SIZE;

    if (result < 8192)
        return 8192;
    return result;

}

int ethaddr_to_string(char* str2write, const struct ether_addr* eth_addr)
{

    return sprintf(str2write, "%02x:%02x:%02x:%02x:%02x:%02x",
                   eth_addr->addr_bytes[0], eth_addr->addr_bytes[1],
                   eth_addr->addr_bytes[2], eth_addr->addr_bytes[3],
                   eth_addr->addr_bytes[4], eth_addr->addr_bytes[5]);
}

/**
 * Starting point of execution.
 */
int main(int argc, char **argv)
{

    int status;

    printf("[[I]] Starting DPDK EAL...\n");

    status = rte_eal_init(argc, argv);
    if (status < 0)
    {
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    }

    printf("[[I]] Checking for ports...\n");

    uint8_t devcount = rte_eth_dev_count();

    if (devcount == 0)
    {
        rte_exit(EXIT_FAILURE, "No probed ethernet devices\n");
        printf("[[I]] No devs, exiting\n");
    }
    printf("[[I]] Found %i net devices.\n", devcount);

    uint8_t i;
    uint8_t our_lcore = 255;
    uint8_t portid;
    unsigned nb_ports;

    for (i = 0; i < RTE_MAX_LCORE; i++)
    {

        if (rte_lcore_is_enabled(i) && !(rte_get_master_lcore() == i))
        {
            //printf("  Adding.\n");
            our_lcore = i;
            break;
        }
    }

    if (our_lcore == 255)
    {
        rte_exit(EXIT_FAILURE, "No lcores were available\n");
    }

    argc -= status;
    argv += status;

    //Find the interior and exterior interface by MAC address...
    printf("[[I]] Associating devices...\n");

    nb_ports = rte_eth_dev_count();

    uint8_t socket = rte_lcore_to_socket_id(our_lcore);
    //We are on this socket, necessary for NUMA

    //Set up a mempool for packets

    printf("[[I]] Configuring mempool...\n");
    unsigned mempool_sz = tz_getMBufMempoolSize(1, 1, 1, 1);
    mempool = rte_mempool_create("DEFAULT_MEMPOOL",
                                 mempool_sz, //The number of elements in the mempool. n = (2^q - 1).
                                 MBUF_SIZE,	//Size of each element
                                 MEMPOOL_CACHE_SIZE, sizeof(struct rte_pktmbuf_pool_private),
                                 rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL, socket, 0);

    if (mempool == NULL)
        rte_exit(EXIT_FAILURE, "MBuf creation failed for interface %i\n", i);

    for (portid = 0; portid < nb_ports; portid++)
    {
        if (port_init(portid, mempool) == 0)
        {
            pppoe_enabled_ports[pppoe_enabled_port_nb] = portid;
            pppoe_enabled_port_nb++;
        }
        else
        {
            rte_exit(EXIT_FAILURE,
                     "Cannot init port %"PRIu8 "\n",
                     portid);
        }

        //Wait for ports up
        printf("[[I]] Waiting for ports up...\n");

        struct rte_eth_link link;
        int up = 0;
        while (1)
        {
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(ETHDEV_ID, &link);
            printf("  Link ");
            if (link.link_status)
            {
                printf("up\n");
                up = 1;
                break;
            }
            else
            {
                printf("down\n");
            }
            rte_delay_ms(200);
        }
    }

    printf("[[I]] Launching data plane cores...\n");
    init_ring();
    rte_eal_remote_launch(lcore_slave_job, NULL, our_lcore);
    do_dataplane_job(NULL);
    if (rte_eal_wait_lcore(our_lcore) < 0)
        return -1;

    printf("[[I]] Exiting.\n");

    return 0;

}

