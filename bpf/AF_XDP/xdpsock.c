// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

/*
Application types
0 = MAC swap and drop 
1 = Read every cache line
2 = Write every cache line
3 = Huge calculation (Compute prime numbers)
4 = Some packets take more time (say every 10000 thpacket)
5 = MAC swap and forward
*/

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <locale.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <math.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"
#include <sys/stat.h>
#include <x86intrin.h>

#include "../lib/xdp-tools/headers/xdp/xsk.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif

#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 9728 /* Max frame size supported by many NICs */
#define IS_EOP_DESC(options) (!((options) & XDP_PKT_CONTD))


#define NSEC_PER_SEC		1000000000UL
#define NSEC_PER_USEC		1000

#define SCHED_PRI__DEFAULT	0
#define STRERR_BUFSIZE          1024

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

static unsigned long prev_time;


static enum xdp_attach_mode opt_attach_mode = XDP_MODE_NATIVE;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_queue;
static unsigned long opt_duration;
static unsigned long start_time;
static bool benchmark_done;
static u16 opt_pkt_size = MIN_PKT_SIZE;
static int opt_poll;
static int opt_interval = 1;
static int opt_retries = 3;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_unaligned_chunks;
static int opt_mmap_flags;
static int frames_per_pkt;
static int opt_timeout = 1000;
static bool opt_need_wakeup = true;
static u32 opt_num_xsks = 1;
static bool opt_busy_poll;
static clockid_t opt_clock = CLOCK_MONOTONIC;
static int opt_schpolicy = SCHED_OTHER;
static int opt_schprio = SCHED_PRI__DEFAULT;
static struct xdp_program *xdp_prog;
static bool load_xdp_prog;

////////////// Application type variables ////////////////
int opt_application_type = 0;

///////////// Configuration variables ////////////////

// queue sizes: Changing umem sizes changes their size accordingly -U
static u64 umem_size = 4096;
static u32 fq_size = 4096;
static u32 cq_size = 2048;
static u32 rx_queue_size = 2048;
static u32 tx_queue_size = 2048;
static u32 num_fq_desc = 4096;

// Frame size -f
static int opt_xsk_frame_size = 4096;

// Batch size -b
static u32 opt_batch_size = 64;

// Address multiplier
static int multiplier = 4096;
static int opt_packet_size = 512;

static bool opt_complete_umem;

////////////// Packet related variables //////////////

static u64 prev_addr = 0;
static u64 out_of_order = 0;

static int dummy_count;

static int dummy_primes = 0;

static int pkt_count=0;
/////////////// Warm buffers & addresses  ////////////
static bool opt_warm_buffers = false;

static long long warm_count;
static long long cold_count;
static long long prev_prod = 16384;
static long long prev_cons = 0;
struct addr_info{
	u32 number;
	u64 addr;
	u32 len;
};

static int to_add =-1;
u64 prev_consumer =0;

#define MAX_ADDRESS_COUNT 16384
struct addr_info addr_array[MAX_ADDRESS_COUNT];
static int addr_count =0;

u64 address_counting [16384];

static bool opt_debug_addr = false;
static const char *addr_file = "";
char addr_file_path[256];
///////////////// Software Prefetching //////////////

static bool opt_spf = false;

/////////////// Dynamic ring ///////////////

static bool opt_dynamic_ring = false;

struct sigevent sev_monitor;
timer_t timerid_monitor;
struct itimerspec  its_monitor;


int monitor_secs = 0;
int monitor_nsecs =100000;

u32 prev_producer;
long long prev_drop;
long long prev_rcvd;
long long prev_diff;

const char *interface = "ens19f0np0";

/////////////////////////////////////

struct xsk_ring_stats {
	unsigned long rx_frags;
	unsigned long rx_npkts;
	unsigned long tx_frags;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;
	unsigned long prev_rx_frags;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_frags;
	unsigned long prev_tx_npkts;
	unsigned long prev_rx_dropped_npkts;
	unsigned long prev_rx_invalid_npkts;
	unsigned long prev_tx_invalid_npkts;
	unsigned long prev_rx_full_npkts;
	unsigned long prev_rx_fill_empty_npkts;
	unsigned long prev_tx_empty_npkts;
};

struct xsk_driver_stats {
	unsigned long intrs;
	unsigned long prev_intrs;
};

struct xsk_app_stats {
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long tx_wakeup_sendtos;
	unsigned long opt_polls;
	unsigned long prev_rx_empty_polls;
	unsigned long prev_fill_fail_polls;
	unsigned long prev_copy_tx_sendtos;
	unsigned long prev_tx_wakeup_sendtos;
	unsigned long prev_opt_polls;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	struct xsk_ring_stats ring_stats;
	struct xsk_app_stats app_stats;
	struct xsk_driver_stats drv_stats;
	u32 outstanding_tx;
};

static const struct clockid_map {
	const char *name;
	clockid_t clockid;
} clockids_map[] = {
	{ "REALTIME", CLOCK_REALTIME },
	{ "TAI", CLOCK_TAI },
	{ "BOOTTIME", CLOCK_BOOTTIME },
	{ "MONOTONIC", CLOCK_MONOTONIC },
	{ NULL }
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;

////////////// Processing time functions /////////////

static bool inline  is_prime(long long num) {
    if (num <= 1) return false;
    if (num == 2 || num == 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;

    for (long long i = 5; i <= num/2; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }
    return true;
}

static int inline get_prime_count(long long limit){

	int counts=0;
	for(long long i=1; i<limit;i++)
	{
		if(is_prime(i))
			counts++;
	}

	return counts;
}

////////////////////////////////////////////////////////

static void inline prefetch_packet(void* addr)
{
	char *pkt = (char*)addr;
	__builtin_prefetch(&pkt[0],1,3);

	if(opt_application_type == 2 || opt_application_type == 1){
		for(int i =1; i< opt_packet_size; i+=64)
		{	
			if(opt_application_type==2)
			__builtin_prefetch(&pkt[i],1,3);
			else
			__builtin_prefetch(&pkt[i],0,3);
		}
	}
}

////////////////// Dynamic ring size ////////////////////////////////////

// fills in received and dropped packets in passed array.
static inline void get_pkt_stats_since_last(long long arr[2])
{
	FILE *fp;
	char line[512];
	char iface[64];

	long long rcvd_pkts = 0;
	long long dropped_pkts = 0;

	// Open /proc/net/dev
	fp = fopen("/proc/net/dev", "r");
	if (fp == NULL)
		perror("Failed to open /proc/net/dev");

	// Skip the first two header lines
	if(fgets(line, sizeof(line), fp)==NULL)
		perror("Could not read proc file");
	if(fgets(line, sizeof(line), fp)==NULL)
		perror("Could not read proc file");

	// Read each line and check for the desired interface
	while (fgets(line, sizeof(line), fp) != NULL)
	{
		sscanf(line, "%63[^:]", iface); // Extract the interface name
		if (strcmp(iface, interface) == 0)
		{
			// Tokenize the string
			char *token = strtok(line, " ");
			int column = 1;

			// Get column 3 and 5
			while (token != NULL)
			{
				if (column == 3)
					rcvd_pkts = strtoll(token, NULL, 10);

				if (column == 5)
				{
					dropped_pkts = strtoll(token, NULL, 10);
					break;
				}
				column++;
				token = strtok(NULL, " ");
			}
			break;
		}
	}

	long long dropped = dropped_pkts - prev_drop;
	long long received = rcvd_pkts - prev_rcvd;
	arr[0] = received;
	arr[1] = dropped;
	prev_drop=dropped_pkts;
	prev_rcvd = rcvd_pkts;
	fclose(fp);
}

static inline long long get_warm_buffers_since_last()
{
	long long diff =0;
	struct xsk_socket_info *xsk = xsks[0];
	u32 current_producer = *xsk->umem->fq.producer;
	if(current_producer >= prev_producer)
		diff = current_producer - prev_producer;
	else
		diff = prev_diff;
	
	prev_diff = diff;
	prev_producer = current_producer;
	return diff;
	
}

static inline void create_timer()
{
	// Create timer
	sev_monitor.sigev_notify = SIGEV_SIGNAL;
	sev_monitor.sigev_signo = SIGALRM;
	sev_monitor.sigev_value.sival_ptr = &timerid_monitor;
	if (timer_create(CLOCK_REALTIME, &sev_monitor, &timerid_monitor) == -1)
		perror("timer create");
}

static inline void start_timer()
{
	// start timer with interval of 1 sec
	its_monitor.it_value.tv_sec = monitor_secs;
	its_monitor.it_value.tv_nsec = monitor_nsecs;
	its_monitor.it_interval.tv_sec = monitor_secs;
	its_monitor.it_interval.tv_nsec = monitor_nsecs;
	if (timer_settime(timerid_monitor, 0, &its_monitor, NULL) == -1)
		perror("timer_settime");
}

static void timer_handler(int sig)
{
	long long stats[2];
	get_pkt_stats_since_last(stats);
	long long warm_buffers = get_warm_buffers_since_last();
	printf("Received:%lld Dropped:%lld Warm:%lld\n",stats[0],stats[1],warm_buffers);
}

//////////////////////////////////////////////////////
static int get_clockid(clockid_t *id, const char *name)
{
	const struct clockid_map *clk;

	for (clk = clockids_map; clk->name; clk++) {
		if (strcasecmp(clk->name, name) == 0) {
			*id = clk->clockid;
			return 0;
		}
	}

	return -1;
}

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(opt_clock, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}


static int xsk_get_xdp_stats(int fd, struct xsk_socket_info *xsk)
{
	struct xdp_statistics stats;
	socklen_t optlen;
	int err;

	optlen = sizeof(stats);
	err = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(struct xdp_statistics)) {
		xsk->ring_stats.rx_dropped_npkts = stats.rx_dropped;
		xsk->ring_stats.rx_invalid_npkts = stats.rx_invalid_descs;
		xsk->ring_stats.tx_invalid_npkts = stats.tx_invalid_descs;
		xsk->ring_stats.rx_full_npkts = stats.rx_ring_full;
		xsk->ring_stats.rx_fill_empty_npkts = stats.rx_fill_ring_empty_descs;
		xsk->ring_stats.tx_empty_npkts = stats.tx_ring_empty_descs;
		return 0;
	}

	return -EINVAL;
}

static void  debug_addresses()
{
		FILE *file = fopen(addr_file_path, "a");
		if (file == NULL) {
			perror("Error opening file");
		}
		for(u32 i = 0; i < addr_count; i++)
		{
			fprintf(file, "number:%u	address:%llu	length:%u   count: %llu\n",addr_array[i].number,
					addr_array[i].addr/opt_xsk_frame_size,addr_array[i].len,address_counting[addr_array[i].addr/opt_xsk_frame_size]);
		}

		fclose(file);
}


void post_exp_process()
{
	FILE *file = fopen("./logs/stats.csv", "w");
	if (file == NULL) {
		perror("Error opening file");
	}
	for (int i = 0; i < num_socks && xsks[i]; i++) {
		if (!xsk_get_xdp_stats(xsk_socket__fd(xsks[i]->xsk), xsks[i])){
			fprintf(file, "rx_packets,%lu\n",xsks[i]->ring_stats.rx_npkts);
			fprintf(file, "rx_dropped,%lu\n",xsks[i]->ring_stats.rx_dropped_npkts);
			fprintf(file, "rx_invalid,%lu\n",xsks[i]->ring_stats.rx_invalid_npkts);
			fprintf(file, "rx_queue_full,%lu\n",xsks[i]->ring_stats.rx_full_npkts);
			fprintf(file, "fill_ring_empty,%lu\n",xsks[i]->ring_stats.rx_fill_empty_npkts);
			fprintf(file, "out_of_order,%llu\n",out_of_order-(xsks[i]->ring_stats.rx_npkts/umem_size));
			// Warm buffer count
			fprintf(file, "warm_count,%lld\n",warm_count);
			fprintf(file, "cold_count,%lld\n",cold_count);
			// Write dummy count to avoid compiler optimization
			fprintf(file, "dummy_count,%d\n",dummy_count);
			fprintf(file, "dummy_primes,%d\n",dummy_primes);
		}
	}
	fclose(file);

	if(opt_debug_addr)
		debug_addresses();
}

static void remove_xdp_program(void)
{
	int err;

	err = xdp_program__detach(xdp_prog, opt_ifindex, opt_attach_mode, 0);
	if (err)
		fprintf(stderr, "Could not detach XDP program. Error: %s\n", strerror(-err));
}

static void int_exit(int sig)
{
	timer_delete(timerid_monitor);
	benchmark_done = true;
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	if (load_xdp_prog)
		remove_xdp_program();
	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void xdpsock_cleanup(void)
{
	struct xsk_umem *umem = xsks[0]->umem->umem;
	int i;

	for (i = 0; i < num_socks; i++)
		xsk_socket__delete(xsks[i]->xsk);
	(void)xsk_umem__delete(umem);


	if (load_xdp_prog)
		remove_xdp_program();
}

static void inline process_packet(void *data, size_t length, u64 addr)
{
	// flag for kernel
	
	char *ptr1 = (char*) data;
	ptr1[5] = 'W';

	pkt_count++;

	if(!(opt_application_type==2|| opt_application_type == 1)){
	// swap mac addresses
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
	}


	// check for out of order packets
	if(addr - prev_addr != multiplier)
		out_of_order++;
	prev_addr = addr;


	if(opt_application_type == 2)
	{
		unsigned char *pkt = (unsigned char *)data;
		for(int i =0; i< length; i+=64)
			pkt[i] = pkt[i+1];
	}
	if(opt_application_type == 1)
	{
		unsigned char *pkt = (unsigned char *)data;
		for(int i =0; i<length;i+=64)
		{
			if(pkt[i]=='a')
				dummy_count++;
		}

	}
	if(opt_application_type == 3 ){
		dummy_primes+=get_prime_count(100);
	}

	if (opt_application_type == 4)
	{
		if(pkt_count >10000)
		{
			pkt_count = 0;
			dummy_primes+=get_prime_count(100);
		}
	}
}


#define ETH_FCS_SIZE 4

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		/* We recommend that you set the fill ring size >= HW RX ring size +
		 * AF_XDP RX ring size. Make sure you fill up the fill ring
		 * with buffers at regular intervals, and you will with this setting
		 * avoid allocation failures in the driver. These are usually quite
		 * expensive since drivers have not been written to assume that
		 * allocation failures are common. For regular sockets, kernel
		 * allocated memory is used that only runs out in OOM situations
		 * that should be rare.
		 */
		.fill_size = fq_size,
		.comp_size = cq_size,
		.frame_size = opt_xsk_frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = opt_umem_flags
	};
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		exit_with_error(errno);

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       &cfg);
	if (ret)
		exit_with_error(-ret);

	umem->buffer = buffer;
	return umem;
}

static void xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
	int ret, i;
	u32 idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     num_fq_desc, &idx);
	if (ret != num_fq_desc)
		exit_with_error(-ret);

	// Fill initial address
	for (i = 0; i < num_fq_desc; i++){
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * multiplier;
	}

	xsk_ring_prod__submit(&umem->fq, num_fq_desc);
}

static struct xsk_socket_info *xsk_configure_socket(struct xsk_umem_info *umem,
						    bool rx, bool tx)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		exit_with_error(errno);

	xsk->umem = umem;
	cfg.rx_size = rx_queue_size;
	cfg.tx_size = tx_queue_size;
	if (load_xdp_prog )
		cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	else
		cfg.libxdp_flags = 0;
	if (opt_attach_mode == XDP_MODE_SKB)
		cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	else
		cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
	cfg.bind_flags = opt_xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;
	ret = xsk_socket__create(&xsk->xsk, opt_if, opt_queue, umem->umem,
				 rxr, txr, &cfg);
	if (ret)
		exit_with_error(-ret);

	xsk->app_stats.rx_empty_polls = 0;
	xsk->app_stats.fill_fail_polls = 0;
	xsk->app_stats.copy_tx_sendtos = 0;
	xsk->app_stats.tx_wakeup_sendtos = 0;
	xsk->app_stats.opt_polls = 0;
	xsk->app_stats.prev_rx_empty_polls = 0;
	xsk->app_stats.prev_fill_fail_polls = 0;
	xsk->app_stats.prev_copy_tx_sendtos = 0;
	xsk->app_stats.prev_tx_wakeup_sendtos = 0;
	xsk->app_stats.prev_opt_polls = 0;

	return xsk;
}

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"queue", required_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"interval", required_argument, 0, 'n'},
	{"retries", required_argument, 0, 'O'},
	{"zero-copy", no_argument, 0, 'z'},
	{"copy", no_argument, 0, 'c'},
	{"frame-size", required_argument, 0, 'f'},
	{"no-need-wakeup", no_argument, 0, 'm'},
	{"unaligned", no_argument, 0, 'u'},
	{"shared-umem", no_argument, 0, 'M'},
	{"duration", required_argument, 0, 'd'},
	{"clock", required_argument, 0, 'w'},
	{"batch-size", required_argument, 0, 'b'},	
	{"busy-poll", no_argument, 0, 'B'},
	{"UMEM-size", required_argument, 0, 'U'},
	{"huge-pages", no_argument, 0, 'h'},
	{"Warm-buffers", no_argument, 0, 'W'},
	{"packet-size", required_argument, 0, 's'},
	{"Complete-umem", no_argument, 0, 'C'},
	{"soft-pf", no_argument, 0, 'P'},
	{"debug-addr", required_argument, 0, 'D'},
	{"dynamic-ring", no_argument, 0, 'R'},
	{"app-type", required_argument, 0, 'A'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -q, --queue=n	Use queue n (default 0)\n"
		"  -p, --poll		Use poll syscall\n"
		"  -S, --xdp-skb=n	Use XDP skb-mod\n"
		"  -N, --xdp-native=n	Enforce XDP native mode\n"
		"  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
		"  -O, --retries=n	Specify time-out retries (1s interval) attempt (default 3).\n"
		"  -z, --zero-copy      Force zero-copy mode.\n"
		"  -c, --copy           Force copy mode.\n"
		"  -m, --no-need-wakeup Turn off use of driver need wakeup flag.\n"
		"  -f, --frame-size=n   Set the frame size (must be a power of two in aligned mode, default is %d).\n"
		"  -u, --unaligned	Enable unaligned chunk placement\n"
		"  -M, --shared-umem	Enable XDP_SHARED_UMEM (cannot be used with -R)\n"
		"  -d, --duration=n	Duration in secs to run command.\n"
		"			Default: forever.\n"
		"  -w, --clock=CLOCK	Clock NAME (default MONOTONIC).\n"
		"  -b, --batch-size=n	Batch size for sending or receiving\n"
		"			packets. Default: %d\n"
		"  -B, --busy-poll      Busy poll.\n"
		"  -U, --UMEM-size=n      Set UMEM size.\n"
		"  -h, --huge-pages      Use huge pages for umem.\n"
		"  -W, --Warm-buffers      Use recently read buffers first.\n"
		"  -s, --packet-size=n   Specify the incoming packet size for better unaligned mode.\n"
		"  -C, --Complete-umem   Use entire umem in unaligned mode. Extend fill queue as needed\n"
		"  -P, --soft-pf   Software prefetch next buffers \n"
		"  -D, --debug-addr=file	Write addresses to file \n"
		"  -R, --dynamic-ring	Dynamically change ring size \n"
		"  -A, --app-type=type	Application type(0,1,2,3,4,5) \n"
		"\n";
	fprintf(stderr, str, prog, opt_xsk_frame_size,
		opt_batch_size,SCHED_PRI__DEFAULT);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv,
				"i:q:pSNn:w:O:czf:muMd:b:BU:hWs:CPD:RA:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opt_if = optarg;
			break;
		case 'q':
			opt_queue = atoi(optarg);
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'S':
			opt_attach_mode = XDP_MODE_SKB;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'n':
			opt_interval = atoi(optarg);
			break;
		case 'w':
			if (get_clockid(&opt_clock, optarg)) {
				fprintf(stderr,
					"ERROR: Invalid clock %s. Default to CLOCK_MONOTONIC.\n",
					optarg);
				opt_clock = CLOCK_MONOTONIC;
			}
			break;
		case 'O':
			opt_retries = atoi(optarg);
			break;
		case 'z':
			opt_xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'c':
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'u':
			opt_umem_flags |= XDP_UMEM_UNALIGNED_CHUNK_FLAG;
			opt_unaligned_chunks = 1;
			opt_mmap_flags = MAP_HUGETLB;
			break;
		case 'f':
			opt_xsk_frame_size = atoi(optarg);
			multiplier = opt_xsk_frame_size;
			break;
		case 'm':
			opt_need_wakeup = false;
			opt_xdp_bind_flags &= ~XDP_USE_NEED_WAKEUP;
			break;
		case 'M':
			opt_num_xsks = MAX_SOCKS;
			break;
		case 'd':
			opt_duration = atoi(optarg);
			opt_duration *= 1000000000;
			break;
		case 'b':
			opt_batch_size = atoi(optarg);
			break;
		case 'B':
			opt_busy_poll = 1;
			break;
		case 'U':
			umem_size = atoi(optarg);
			fq_size = umem_size;
			cq_size = umem_size/2;
			rx_queue_size = umem_size/2;
			tx_queue_size = umem_size/2;
			num_fq_desc = umem_size;
			prev_producer = fq_size;
			break;
		case 'h':
			opt_mmap_flags = MAP_HUGETLB;
			break;
		case 'W':
			opt_warm_buffers = 1;
			break;
		case 's':
			opt_packet_size = atoi(optarg);
			break;
		case 'C':
			opt_complete_umem = 1;
			break;
		case 'P':
			opt_spf = 1;
			break;
		case 'D':
			opt_debug_addr =1;
			addr_file = optarg;
			break;
		case 'R':
			opt_dynamic_ring =1;
			break;
		case 'A':
			opt_application_type = atoi(optarg);
			if(opt_application_type == 0)
				printf("MAC swap and drop\n");
			else if(opt_application_type == 1)
				printf("Read every cache line\n");
			else if(opt_application_type == 2)
				printf("Write every cache line\n");
			else if(opt_application_type == 3)
				printf("Huge computation\n");
			else if(opt_application_type == 4)
				printf("Some packets take time\n");
			else if(opt_application_type == 5)
				printf("MAC swap and forward\n");

			break;
		default:
			usage(basename(argv[0]));
		}
	}

	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex) {
		fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
			opt_if);
		usage(basename(argv[0]));
	}

	if ((opt_xsk_frame_size & (opt_xsk_frame_size - 1)) &&
	    !opt_unaligned_chunks) {
		fprintf(stderr, "--frame-size=%d is not a power of two\n",
			opt_xsk_frame_size);
		usage(basename(argv[0]));
	}

	load_xdp_prog = (opt_num_xsks > 1 );

}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_forward(struct xsk_socket_info *xsk)
{
	struct xsk_umem_info *umem = xsk->umem;
	u32 idx_cq = 0, idx_fq = 0;
	unsigned int rcvd;
	size_t ndescs;

	if (!xsk->outstanding_tx)
		return;

	/* In copy mode, Tx is driven by a syscall so we need to use e.g. sendto() to
	 * really send the packets. In zero-copy mode we do not have to do this, since Tx
	 * is driven by the NAPI loop. So as an optimization, we do not have to call
	 * sendto() all the time in zero-copy mode for l2fwd.
	 */
	if (opt_xdp_bind_flags & XDP_COPY) {
		xsk->app_stats.copy_tx_sendtos++;
		kick_tx(xsk);
	}

	ndescs = (xsk->outstanding_tx > opt_batch_size) ? opt_batch_size :
		xsk->outstanding_tx;

	/* re-add completed Tx buffers */
	rcvd = xsk_ring_cons__peek(&umem->cq, ndescs, &idx_cq);
	if (rcvd > 0) {
		unsigned int i;
		int ret;

		ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		while (ret != rcvd) {
			if (ret < 0)
				exit_with_error(-ret);
			if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&umem->fq)) {
				xsk->app_stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			}
			ret = xsk_ring_prod__reserve(&umem->fq, rcvd, &idx_fq);
		}

		// check if consumer has changed
		u64 current_cons = *xsk->umem->fq.consumer;
		if(current_cons != prev_consumer)
			to_add =0;

		prev_consumer = current_cons;

		for (i = 0; i < rcvd; i++)
		{
			u64 orig = *xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);

			if(opt_warm_buffers)
				custom_xsk_ring_prod__fill_addr(&umem->fq,idx_fq++,orig,(to_add+i));
			else
				*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) = orig;
		}
		to_add+=rcvd;

		xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}


static void forward(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, idx_tx = 0, frags_done = 0;
	unsigned int rcvd, i, eop_cnt = 0;
	static u32 nb_frags;
	int ret;

	complete_tx_forward(xsk);

	// check if batch ready to receive
	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return;
	}

	// reserve the tx ring to put back the addresses
	ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		complete_tx_forward(xsk);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
			xsk->app_stats.tx_wakeup_sendtos++;
			kick_tx(xsk);
		}
		ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	}

	// process each packets and put back the addresses of buffers
	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		bool eop = IS_EOP_DESC(desc->options);
		u64 addr = desc->addr;
		u32 len = desc->len;
		u64 orig = xsk_umem__extract_addr(addr);

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		if (!nb_frags++){
			process_packet(pkt,len,addr);

		}

		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++);

		tx_desc->options = eop ? 0 : XDP_PKT_CONTD;
		tx_desc->addr = orig;
		tx_desc->len = len;

		if(opt_debug_addr && addr_count < MAX_ADDRESS_COUNT-1){
			addr_array[addr_count].number = i;
			addr_array[addr_count].addr = addr;
			addr_array[addr_count].len = len;
			address_counting[addr/opt_xsk_frame_size]++;
			addr_count++;
		}

		if (eop) {
			frags_done += nb_frags;
			nb_frags = 0;
			eop_cnt++;
		}
	}

	// submit to the tx ring
	xsk_ring_prod__submit(&xsk->tx, frags_done);
	// release the rx buffers
	xsk_ring_cons__release(&xsk->rx, frags_done);

	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.tx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;
	xsk->ring_stats.tx_frags += rcvd;
	xsk->outstanding_tx += frags_done;


	if( prev_cons != *xsk->umem->fq.consumer)
	{
		int cons_move = *xsk->umem->fq.consumer - prev_cons;
		int prod_move = *xsk->umem->fq.producer - prev_prod;
		prev_cons = *xsk->umem->fq.consumer; 
		prev_prod = *xsk->umem->fq.producer;

		if(cons_move > prod_move)
			cold_count += cons_move - prod_move;

		warm_count += prod_move;

	}
	

}

static void receive(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, idx_fq = 0, frags_done = 0;
	unsigned int rcvd, i, eop_cnt = 0;
	static u32 nb_frags;
	int ret;

	// check if batch ready to receive
	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return;
	}

	// reserve the fill queue to put back the addresses
	ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.fill_fail_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq);
	}


	// check if consumer has changed
	u64 current_cons = *xsk->umem->fq.consumer;
	if(current_cons != prev_consumer)
		to_add =0;

	prev_consumer = current_cons;

	// process each packets and put back the addresses of buffers
	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);

		bool eop = IS_EOP_DESC(desc->options);
		u64 addr = desc->addr;
		u32 len = desc->len;
		u64 orig = xsk_umem__extract_addr(addr);


		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		if(opt_spf){
			const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, (idx_rx+1));
			u64 addr = desc->addr;
			char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
			prefetch_packet(pkt);
	}

		if (!nb_frags++){ 
			process_packet(pkt,len,addr);
		}


		if(opt_debug_addr && addr_count < MAX_ADDRESS_COUNT-1){
			addr_array[addr_count].number = i;
			addr_array[addr_count].addr = addr;
			addr_array[addr_count].len = len;
			address_counting[addr/opt_xsk_frame_size]++;
			addr_count++;
		}


		if (eop) {
			frags_done += nb_frags;
			nb_frags = 0;
			eop_cnt++;
		}

		if(opt_warm_buffers)
			custom_xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++,orig,(to_add + i));
		else
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = orig;
	}
	to_add+=rcvd;

	// submit the fill queue
	xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
	// release the rx buffers
	xsk_ring_cons__release(&xsk->rx, frags_done);

	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;

	if( prev_cons != *xsk->umem->fq.consumer)
	{
		int cons_move = *xsk->umem->fq.consumer - prev_cons;
		int prod_move = *xsk->umem->fq.producer - prev_prod;
		prev_cons = *xsk->umem->fq.consumer; 
		prev_prod = *xsk->umem->fq.producer;

		if(cons_move > prod_move)
			cold_count += cons_move - prod_move;

		warm_count += prod_move;

	}
}

static void receive_all(void)
{
	struct pollfd fds[MAX_SOCKS] = {};
	int i, ret;

	for (i = 0; i < num_socks; i++) {
		fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
		fds[i].events = POLLIN | POLLOUT; 
	}

	for (;;) {
		if (opt_poll) {
			for (i = 0; i < num_socks; i++) 
				xsks[i]->app_stats.opt_polls++;

			ret = poll(fds, num_socks, opt_timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++){
			if(opt_application_type == 5)
				forward(xsks[i]);
			else
				receive(xsks[i]);
		}

		if (benchmark_done)
			break;
	}

	post_exp_process();
}

static void load_xdp_program(void)
{
	char errmsg[STRERR_BUFSIZE];
	int err;

	xdp_prog = xdp_program__open_file("xdpsock_kern.o", NULL, NULL);
	err = libxdp_get_error(xdp_prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

	err = xdp_program__set_xdp_frags_support(xdp_prog, false);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: Enable frags support failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

	err = xdp_program__attach(xdp_prog, opt_ifindex, opt_attach_mode, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}
}

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -ENOENT;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -ENOMEM;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}

static void enter_xsks_into_map(void)
{
	struct bpf_map *data_map;
	int i, xsks_map;
	int key = 0;

	data_map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp_prog), ".bss");
	if (!data_map || !bpf_map__is_internal(data_map)) {
		fprintf(stderr, "ERROR: bss map found!\n");
		exit(EXIT_FAILURE);
	}
	if (bpf_map_update_elem(bpf_map__fd(data_map), &key, &num_socks, BPF_ANY)) {
		fprintf(stderr, "ERROR: bpf_map_update_elem num_socks %d!\n", num_socks);
		exit(EXIT_FAILURE);
	}
	xsks_map = lookup_bpf_map(xdp_program__fd(xdp_prog));
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
			exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_socks; i++) {
		int fd = xsk_socket__fd(xsks[i]->xsk);
		int ret;

		key = i;
		ret = bpf_map_update_elem(xsks_map, &key, &fd, 0);
		if (ret) {
			fprintf(stderr, "ERROR: bpf_map_update_elem %d\n", i);
			exit(EXIT_FAILURE);
		}
	}
}

static void apply_setsockopt(struct xsk_socket_info *xsk)
{
	int sock_opt;

	if (!opt_busy_poll)
		return;

	sock_opt = 1;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = 20;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);

	sock_opt = opt_batch_size;
	if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
		       (void *)&sock_opt, sizeof(sock_opt)) < 0)
		exit_with_error(errno);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool rx = false, tx = false;
	struct sched_param schparam;
	struct xsk_umem_info *umem;

	int i, ret;
	void *bufs;

	parse_command_line(argc, argv);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (load_xdp_prog)
		load_xdp_program();

	if(opt_unaligned_chunks){
		multiplier = opt_packet_size;

		if(opt_complete_umem)
		{
			fq_size = (umem_size * opt_xsk_frame_size)/(opt_packet_size);
			rx_queue_size = fq_size/2;
			num_fq_desc = fq_size;
		}
	}

	struct stat st = {0};
    if (stat("./logs", &st) == -1) {
        mkdir("./logs", 0777);
    }

	if(opt_debug_addr)
	{
		snprintf(addr_file_path, sizeof(addr_file_path), "./logs/%s", addr_file);
		FILE *file = fopen(addr_file_path, "w");
		if (file == NULL) {
			perror("Error opening file");
		}
		fclose(file);
	}


	/* Reserve memory for the umem. Use hugepages if unaligned chunk mode */
	bufs = mmap(NULL, umem_size * opt_xsk_frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create sockets... */
	umem = xsk_configure_umem(bufs, umem_size * opt_xsk_frame_size);

	rx = true;
	if(opt_application_type == 5)
		tx = true;

	xsk_populate_fill_ring(umem);
	for (i = 0; i < opt_num_xsks; i++)
		xsks[num_socks++] = xsk_configure_socket(umem, rx, tx);

	for (i = 0; i < opt_num_xsks; i++)
		apply_setsockopt(xsks[i]);


	frames_per_pkt = (opt_pkt_size - 1) / opt_xsk_frame_size + 1;

	if (load_xdp_prog)
		enter_xsks_into_map();


	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	if(opt_dynamic_ring){

		// timer 
		signal(SIGALRM, timer_handler);
		create_timer();
		start_timer();
	}

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();
	start_time = prev_time;


	/* Configure sched priority for better wake-up accuracy */
	memset(&schparam, 0, sizeof(schparam));
	schparam.sched_priority = opt_schprio;
	ret = sched_setscheduler(0, opt_schpolicy, &schparam);
	if (ret) {
		fprintf(stderr, "Error(%d) in setting priority(%d): %s\n",
			errno, opt_schprio, strerror(errno));
		goto out;
	}


	receive_all();

out:
	benchmark_done = true;

	xdpsock_cleanup();

	munmap(bufs, umem_size * opt_xsk_frame_size);

	return 0;
}