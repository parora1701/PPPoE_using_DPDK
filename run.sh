#!/bin/bash

DPDK_DIR=deps/dpdk
DPDK_PLAF=x86_64-native-linuxapp-gcc

#Required kernel modules
modprobe uio
insmod $DPDK_DIR/$DPDK_PLAF/kmod/igb_uio.ko
insmod $DPDK_DIR/$DPDK_PLAF/kmod/rte_kni.ko

#The following must be done for every device we want to use. Only for VirtIO devices this is not required.
$DPDK_DIR/tools/dpdk_nic_bind.py --bind igb_uio 0000:00:08.0

export LD_LIBRARY_PATH=$DPDK_DIR/$DPDK_PLAF/lib
./lab_main -c3 -n4 -d $DPDK_DIR/$DPDK_PLAF/lib/librte_pmd_virtio.so

