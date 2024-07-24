// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Intel Corporation. */

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

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdpsock.h"

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

#define NUM_FRAMES (4 * 1024)
#define MIN_PKT_SIZE 64
#define MAX_PKT_SIZE 9728 /* Max frame size supported by many NICs */
#define IS_EOP_DESC(options) (!((options) & XDP_PKT_CONTD))

#define DEBUG_HEXDUMP 0


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
static u32 opt_batch_size = 64;
static u16 opt_pkt_size = MIN_PKT_SIZE;
static bool opt_extra_stats;
static bool opt_quiet;
static int opt_poll;
static int opt_interval = 1;
static int opt_retries = 3;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_unaligned_chunks;
static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
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

static const struct sched_map {
	const char *name;
	int policy;
} schmap[] = {
	{ "OTHER", SCHED_OTHER },
	{ "FIFO", SCHED_FIFO },
	{ NULL }
};

static int num_socks;
struct xsk_socket_info *xsks[MAX_SOCKS];
int sock;

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

static int get_schpolicy(int *policy, const char *name)
{
	const struct sched_map *sch;

	for (sch = schmap; sch->name; sch++) {
		if (strcasecmp(sch->name, name) == 0) {
			*policy = sch->policy;
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

static void print_benchmark(bool running)
{
	const char *bench_str = "INVALID";

	bench_str = "receive";

	printf("%s:%d %s ", opt_if, opt_queue, bench_str);
	if (opt_attach_mode == XDP_MODE_SKB)
		printf("xdp-skb ");
	else if (opt_attach_mode == XDP_MODE_NATIVE)
		printf("xdp-drv ");
	else
		printf("	");

	if (opt_poll)
		printf("poll() ");

	if (running) {
		printf("running...");
		fflush(stdout);
	}
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

static void dump_stats(void)
{
	unsigned long now = get_nsecs();
	long dt = now - prev_time;
	int i;

	prev_time = now;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double rx_pps, tx_pps, dropped_pps, rx_invalid_pps, full_pps, fill_empty_pps,
			tx_invalid_pps, tx_empty_pps;

		rx_pps = (xsks[i]->ring_stats.rx_npkts - xsks[i]->ring_stats.prev_rx_npkts) *
			 1000000000. / dt;
		tx_pps = (xsks[i]->ring_stats.tx_npkts - xsks[i]->ring_stats.prev_tx_npkts) *
			 1000000000. / dt;

		printf("\n sock%d@", i);
		print_benchmark(false);
		printf("\n");



		printf("%-18s %-14s %-14s %-14.2f\n", "", "pps", "pkts",
				dt / 1000000000.);
		printf(fmt, "rx", rx_pps, xsks[i]->ring_stats.rx_npkts);
		printf(fmt, "tx", tx_pps, xsks[i]->ring_stats.tx_npkts);

		xsks[i]->ring_stats.prev_rx_npkts = xsks[i]->ring_stats.rx_npkts;
		xsks[i]->ring_stats.prev_tx_npkts = xsks[i]->ring_stats.tx_npkts;

		if (opt_extra_stats) {
			if (!xsk_get_xdp_stats(xsk_socket__fd(xsks[i]->xsk), xsks[i])) {
				dropped_pps = (xsks[i]->ring_stats.rx_dropped_npkts -
						xsks[i]->ring_stats.prev_rx_dropped_npkts) *
							1000000000. / dt;
				rx_invalid_pps = (xsks[i]->ring_stats.rx_invalid_npkts -
						xsks[i]->ring_stats.prev_rx_invalid_npkts) *
							1000000000. / dt;
				tx_invalid_pps = (xsks[i]->ring_stats.tx_invalid_npkts -
						xsks[i]->ring_stats.prev_tx_invalid_npkts) *
							1000000000. / dt;
				full_pps = (xsks[i]->ring_stats.rx_full_npkts -
						xsks[i]->ring_stats.prev_rx_full_npkts) *
							1000000000. / dt;
				fill_empty_pps = (xsks[i]->ring_stats.rx_fill_empty_npkts -
						xsks[i]->ring_stats.prev_rx_fill_empty_npkts) *
							1000000000. / dt;
				tx_empty_pps = (xsks[i]->ring_stats.tx_empty_npkts -
						xsks[i]->ring_stats.prev_tx_empty_npkts) *
							1000000000. / dt;

				printf(fmt, "rx dropped", dropped_pps,
				       xsks[i]->ring_stats.rx_dropped_npkts);
				printf(fmt, "rx invalid", rx_invalid_pps,
				       xsks[i]->ring_stats.rx_invalid_npkts);
				printf(fmt, "tx invalid", tx_invalid_pps,
				       xsks[i]->ring_stats.tx_invalid_npkts);
				printf(fmt, "rx queue full", full_pps,
				       xsks[i]->ring_stats.rx_full_npkts);
				printf(fmt, "fill ring empty", fill_empty_pps,
				       xsks[i]->ring_stats.rx_fill_empty_npkts);
				printf(fmt, "tx ring empty", tx_empty_pps,
				       xsks[i]->ring_stats.tx_empty_npkts);

				xsks[i]->ring_stats.prev_rx_dropped_npkts =
					xsks[i]->ring_stats.rx_dropped_npkts;
				xsks[i]->ring_stats.prev_rx_invalid_npkts =
					xsks[i]->ring_stats.rx_invalid_npkts;
				xsks[i]->ring_stats.prev_tx_invalid_npkts =
					xsks[i]->ring_stats.tx_invalid_npkts;
				xsks[i]->ring_stats.prev_rx_full_npkts =
					xsks[i]->ring_stats.rx_full_npkts;
				xsks[i]->ring_stats.prev_rx_fill_empty_npkts =
					xsks[i]->ring_stats.rx_fill_empty_npkts;
				xsks[i]->ring_stats.prev_tx_empty_npkts =
					xsks[i]->ring_stats.tx_empty_npkts;
			} else {
				printf("%-15s\n", "Error retrieving extra stats");
			}
		}
	}

}

static bool is_benchmark_done(void)
{
	if (opt_duration > 0) {
		unsigned long dt = (get_nsecs() - start_time);

		if (dt >= opt_duration)
			benchmark_done = true;
	}
	return benchmark_done;
}

static void *poller(void *arg)
{
	(void)arg;
	while (!is_benchmark_done()) {
		sleep(opt_interval);
		dump_stats();
	}

	return NULL;
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

	dump_stats();
	for (i = 0; i < num_socks; i++)
		xsk_socket__delete(xsks[i]->xsk);
	(void)xsk_umem__delete(umem);


	if (load_xdp_prog)
		remove_xdp_program();
}

static void swap_mac_addresses(void *data)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
}

static void hex_dump(void *pkt, size_t length, u64 addr)
{
	const unsigned char *address = (unsigned char *)pkt;
	const unsigned char *line = address;
	size_t line_size = 32;
	unsigned char c;
	char buf[32];
	int i = 0;

	if (!DEBUG_HEXDUMP)
		return;

	sprintf(buf, "addr=%llu", addr);
	printf("length = %zu\n", length);
	printf("%s | ", buf);
	while (length-- > 0) {
		printf("%02X ", *address++);
		if (!(++i % line_size) || (length == 0 && i % line_size)) {
			if (length == 0) {
				while (i++ % line_size)
					printf("__ ");
			}
			printf(" | ");	/* right close */
			while (line < address) {
				c = *line++;
				printf("%c", (c < 33 || c == 255) ? 0x2E : c);
			}
			printf("\n");
			if (length > 0)
				printf("%s | ", buf);
		}
	}
	printf("\n");
}


#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE (sizeof(struct ethhdr))
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + \
		      sizeof(struct udphdr) )

#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - \
				 (sizeof(struct udphdr)))


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
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
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
				     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		exit_with_error(-ret);
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * opt_xsk_frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
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
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
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
	{"policy", required_argument, 0, 'W'},
	{"schpri", required_argument, 0, 'U'},
	{"extra-stats", no_argument, 0, 'x'},
	{"quiet", no_argument, 0, 'Q'},
	{"busy-poll", no_argument, 0, 'B'},
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
		"  -W, --policy=POLICY  Schedule policy. Default: SCHED_OTHER\n"
		"  -U, --schpri=n       Schedule priority. Default: %d\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -Q, --quiet          Do not display any stats.\n"
		"  -B, --busy-poll      Busy poll.\n"
		"\n";
	fprintf(stderr, str, prog, XSK_UMEM__DEFAULT_FRAME_SIZE,
		opt_batch_size, MIN_PKT_SIZE, MIN_PKT_SIZE,
		MAX_PKT_SIZE, 
		SCHED_PRI__DEFAULT);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv,
				"i:q:pSNn:w:O:czf:muMd:b:W:U:xQB",
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
		case 'W':
			if (get_schpolicy(&opt_schpolicy, optarg)) {
				fprintf(stderr,
					"ERROR: Invalid policy %s. Default to SCHED_OTHER.\n",
					optarg);
				opt_schpolicy = SCHED_OTHER;
			}
			break;
		case 'U':
			opt_schprio = atoi(optarg);
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'Q':
			opt_quiet = 1;
			break;
		case 'B':
			opt_busy_poll = 1;
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


static void receive(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, frags_done = 0;
	unsigned int rcvd, i, eop_cnt = 0;
	static u32 nb_frags;

	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return;
	}


	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		bool eop = IS_EOP_DESC(desc->options);
		u64 addr = desc->addr;
		u32 len = desc->len;

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		if (!nb_frags++)
			swap_mac_addresses(pkt);

		hex_dump(pkt, len, addr);

		if (eop) {
			frags_done += nb_frags;
			nb_frags = 0;
			eop_cnt++;
		}
	}

	xsk_ring_cons__release(&xsk->rx, frags_done);

	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;
}

static void receive_all(void)
{
	struct pollfd fds[MAX_SOCKS] = {};
	int i, ret;

	for (;;) {
		if (opt_poll) {
			for (i = 0; i < num_socks; i++) {
				fds[i].fd = xsk_socket__fd(xsks[i]->xsk);
				fds[i].events = POLLOUT | POLLIN;
				xsks[i]->app_stats.opt_polls++;
			}
			ret = poll(fds, num_socks, opt_timeout);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < num_socks; i++)
			receive(xsks[i]);

		if (benchmark_done)
			break;
	}
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

	pthread_t pt;
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


	/* Reserve memory for the umem. Use hugepages if unaligned chunk mode */
	bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
		    PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
	if (bufs == MAP_FAILED) {
		printf("ERROR: mmap failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create sockets... */
	umem = xsk_configure_umem(bufs, NUM_FRAMES * opt_xsk_frame_size);

	rx = true;
	xsk_populate_fill_ring(umem);
	tx = true;
	for (i = 0; i < opt_num_xsks; i++)
		xsks[num_socks++] = xsk_configure_socket(umem, rx, tx);

	for (i = 0; i < opt_num_xsks; i++)
		apply_setsockopt(xsks[i]);


	frames_per_pkt = (opt_pkt_size - 1) / XSK_UMEM__DEFAULT_FRAME_SIZE + 1;

	if (load_xdp_prog)
		enter_xsks_into_map();


	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();
	start_time = prev_time;

	if (!opt_quiet) {
		ret = pthread_create(&pt, NULL, poller, NULL);
		if (ret)
			exit_with_error(ret);
	}

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

	if (!opt_quiet)
		pthread_join(pt, NULL);

	xdpsock_cleanup();

	munmap(bufs, NUM_FRAMES * opt_xsk_frame_size);

	return 0;
}
