CC=gcc

# Should contain pre-built DPDK at least.
RTE_SDK=deps/dpdk

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

LDDIRS += -L$(RTE_SDK)/$(RTE_TARGET)/lib	#Here, libdpdk.so should reside.

LDLIBS += -ldpdk
LDLIBS += -ldl
LDLIBS += -lpthread
#LDLIBS += -lxml2 
LDLIBS += -lm

app: lab_main.o
	$(CC) $(LDDIRS) -o lab_main lab_main.o $(LDLIBS)

lab_main.o: lab_main.c lab_task.c
	$(CC) -mssse3 -I../grt -I$(RTE_SDK)/$(RTE_TARGET)/include -c lab_main.c

