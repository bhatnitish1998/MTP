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

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_VID__DEFAULT	1
#define VLAN_PRI__DEFAULT	0

#define NSEC_PER_SEC		1000000000UL
#define NSEC_PER_USEC		1000

#define SCHED_PRI__DEFAULT	0
#define STRERR_BUFSIZE          1024

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

static unsigned long prev_time;


enum benchmark_type {
	BENCH_RXDROP = 0,
	BENCH_TXONLY = 1,
	BENCH_L2FWD = 2,
};

static enum benchmark_type opt_bench = BENCH_L2FWD;
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
static bool opt_app_stats;
static const char *opt_irq_str = "";
static u32 irq_no;
static int irqs_at_init = -1;
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

struct vlan_ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#define PKTGEN_MAGIC 0xbe9be955
struct pktgen_hdr {
	__be32 pgh_magic;
	__be32 seq_num;
	__be32 tv_sec;
	__be32 tv_usec;
};

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

	if (opt_bench == BENCH_L2FWD)
		bench_str = "l2fwd";

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

static void dump_app_stats(long dt)
{
	int i;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double rx_empty_polls_ps, fill_fail_polls_ps, copy_tx_sendtos_ps,
				tx_wakeup_sendtos_ps, opt_polls_ps;

		rx_empty_polls_ps = (xsks[i]->app_stats.rx_empty_polls -
					xsks[i]->app_stats.prev_rx_empty_polls) * 1000000000. / dt;
		fill_fail_polls_ps = (xsks[i]->app_stats.fill_fail_polls -
					xsks[i]->app_stats.prev_fill_fail_polls) * 1000000000. / dt;
		copy_tx_sendtos_ps = (xsks[i]->app_stats.copy_tx_sendtos -
					xsks[i]->app_stats.prev_copy_tx_sendtos) * 1000000000. / dt;
		tx_wakeup_sendtos_ps = (xsks[i]->app_stats.tx_wakeup_sendtos -
					xsks[i]->app_stats.prev_tx_wakeup_sendtos)
										* 1000000000. / dt;
		opt_polls_ps = (xsks[i]->app_stats.opt_polls -
					xsks[i]->app_stats.prev_opt_polls) * 1000000000. / dt;

		printf("\n%-18s %-14s %-14s\n", "", "calls/s", "count");
		printf(fmt, "rx empty polls", rx_empty_polls_ps, xsks[i]->app_stats.rx_empty_polls);
		printf(fmt, "fill fail polls", fill_fail_polls_ps,
							xsks[i]->app_stats.fill_fail_polls);
		printf(fmt, "copy tx sendtos", copy_tx_sendtos_ps,
							xsks[i]->app_stats.copy_tx_sendtos);
		printf(fmt, "tx wakeup sendtos", tx_wakeup_sendtos_ps,
							xsks[i]->app_stats.tx_wakeup_sendtos);
		printf(fmt, "opt polls", opt_polls_ps, xsks[i]->app_stats.opt_polls);

		xsks[i]->app_stats.prev_rx_empty_polls = xsks[i]->app_stats.rx_empty_polls;
		xsks[i]->app_stats.prev_fill_fail_polls = xsks[i]->app_stats.fill_fail_polls;
		xsks[i]->app_stats.prev_copy_tx_sendtos = xsks[i]->app_stats.copy_tx_sendtos;
		xsks[i]->app_stats.prev_tx_wakeup_sendtos = xsks[i]->app_stats.tx_wakeup_sendtos;
		xsks[i]->app_stats.prev_opt_polls = xsks[i]->app_stats.opt_polls;
	}


}

static bool get_interrupt_number(void)
{
	FILE *f_int_proc;
	char line[4096];
	bool found = false;

	f_int_proc = fopen("/proc/interrupts", "r");
	if (f_int_proc == NULL) {
		printf("Failed to open /proc/interrupts.\n");
		return found;
	}

	while (!feof(f_int_proc) && !found) {
		/* Make sure to read a full line at a time */
		if (fgets(line, sizeof(line), f_int_proc) == NULL ||
				line[strlen(line) - 1] != '\n') {
			printf("Error reading from interrupts file\n");
			break;
		}

		/* Extract interrupt number from line */
		if (strstr(line, opt_irq_str) != NULL) {
			irq_no = atoi(line);
			found = true;
			break;
		}
	}

	fclose(f_int_proc);

	return found;
}

static int get_irqs(void)
{
	char count_path[PATH_MAX];
	int total_intrs = -1;
	FILE *f_count_proc;
	char line[4096];

	snprintf(count_path, sizeof(count_path),
		"/sys/kernel/irq/%i/per_cpu_count", irq_no);
	f_count_proc = fopen(count_path, "r");
	if (f_count_proc == NULL) {
		printf("Failed to open %s\n", count_path);
		return total_intrs;
	}

	if (fgets(line, sizeof(line), f_count_proc) == NULL ||
			line[strlen(line) - 1] != '\n') {
		printf("Error reading from %s\n", count_path);
	} else {
		static const char com[2] = ",";
		char *token;

		total_intrs = 0;
		token = strtok(line, com);
		while (token != NULL) {
			/* sum up interrupts across all cores */
			total_intrs += atoi(token);
			token = strtok(NULL, com);
		}
	}

	fclose(f_count_proc);

	return total_intrs;
}

static void dump_driver_stats(long dt)
{
	int i;

	for (i = 0; i < num_socks && xsks[i]; i++) {
		char *fmt = "%-18s %'-14.0f %'-14lu\n";
		double intrs_ps;
		int n_ints = get_irqs();

		if (n_ints < 0) {
			printf("error getting intr info for intr %i\n", irq_no);
			return;
		}
		xsks[i]->drv_stats.intrs = n_ints - irqs_at_init;

		intrs_ps = (xsks[i]->drv_stats.intrs - xsks[i]->drv_stats.prev_intrs) *
			 1000000000. / dt;

		printf("\n%-18s %-14s %-14s\n", "", "intrs/s", "count");
		printf(fmt, "irqs", intrs_ps, xsks[i]->drv_stats.intrs);

		xsks[i]->drv_stats.prev_intrs = xsks[i]->drv_stats.intrs;
	}
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

	if (opt_app_stats)
		dump_app_stats(dt);
	if (irq_no)
		dump_driver_stats(dt);
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

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
	unsigned int result = 0;
	int odd;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long)buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff +
						   ((unsigned int)len & ~3);
			unsigned int carry = 0;

			do {
				unsigned int w = *(unsigned int *)buff;

				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline u32 from64to32(u64 x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	unsigned long long s = (u32)sum;

	s += (u32)saddr;
	s += (u32)daddr;
#ifdef __BIG_ENDIAN__
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline u16 udp_csum(u32 saddr, u32 daddr, u32 len,
			   u8 proto, u16 *udp_pkt)
{
	u32 csum = 0;
	u32 cnt = 0;

	/* udp hdr and data */
	for (; cnt < len; cnt += 2)
		csum += udp_pkt[cnt >> 1];

	return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

#define ETH_FCS_SIZE 4

#define ETH_HDR_SIZE (sizeof(struct ethhdr))
#define PKTGEN_HDR_SIZE (0)
#define PKT_HDR_SIZE (ETH_HDR_SIZE + sizeof(struct iphdr) + \
		      sizeof(struct udphdr) + PKTGEN_HDR_SIZE)
#define PKTGEN_HDR_OFFSET (ETH_HDR_SIZE + sizeof(struct iphdr) + \
			   sizeof(struct udphdr))
#define PKTGEN_SIZE_MIN (PKTGEN_HDR_OFFSET + sizeof(struct pktgen_hdr) + \
			 ETH_FCS_SIZE)

#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - ETH_HDR_SIZE)
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - \
				 (sizeof(struct udphdr) + PKTGEN_HDR_SIZE))


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
	{"app-stats", no_argument, 0, 'a'},
	{"irq-string", no_argument, 0, 'I'},
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
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"  -I, --irq-string	Display driver interrupt statistics for interface associated with irq-string.\n"
		"  -B, --busy-poll      Busy poll.\n"
		"\n";
	fprintf(stderr, str, prog, XSK_UMEM__DEFAULT_FRAME_SIZE,
		opt_batch_size, MIN_PKT_SIZE, MIN_PKT_SIZE,
		MAX_PKT_SIZE, 
		VLAN_VID__DEFAULT, VLAN_PRI__DEFAULT,
		SCHED_PRI__DEFAULT);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv,
				"i:q:pSNn:w:O:czf:muMd:b:W:U:xQaI:B",
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
		case 'a':
			opt_app_stats = 1;
			break;
		case 'I':
			opt_irq_str = optarg;
			if (get_interrupt_number())
				irqs_at_init = get_irqs();
			if (irqs_at_init < 0) {
				fprintf(stderr, "ERROR: Failed to get irqs for %s\n", opt_irq_str);
				usage(basename(argv[0]));
			}
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

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;
	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_l2fwd(struct xsk_socket_info *xsk)
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

		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) =
				*xsk_ring_cons__comp_addr(&umem->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static inline void complete_tx_only(struct xsk_socket_info *xsk,
				    int batch_size)
{
	unsigned int rcvd;
	u32 idx;

	if (!xsk->outstanding_tx)
		return;

	if (!opt_need_wakeup || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
		xsk->app_stats.tx_wakeup_sendtos++;
		kick_tx(xsk);
	}

	rcvd = xsk_ring_cons__peek(&xsk->umem->cq, batch_size, &idx);
	if (rcvd > 0) {
		xsk_ring_cons__release(&xsk->umem->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static inline int get_batch_size(int pkt_cnt)
{
	return opt_batch_size * frames_per_pkt;
}


static void l2fwd(struct xsk_socket_info *xsk)
{
	u32 idx_rx = 0, idx_tx = 0, frags_done = 0;
	unsigned int rcvd, i, eop_cnt = 0;
	static u32 nb_frags;
	int ret;

	complete_tx_l2fwd(xsk);

	rcvd = xsk_ring_cons__peek(&xsk->rx, opt_batch_size, &idx_rx);
	if (!rcvd) {
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
			xsk->app_stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}
		return;
	}

	ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	while (ret != rcvd) {
		if (ret < 0)
			exit_with_error(-ret);
		complete_tx_l2fwd(xsk);
		if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
			xsk->app_stats.tx_wakeup_sendtos++;
			kick_tx(xsk);
		}
		ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
	}

	for (i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
		bool eop = IS_EOP_DESC(desc->options);
		u64 addr = desc->addr;
		u32 len = desc->len;
		u64 orig = addr;

		addr = xsk_umem__add_offset_to_addr(addr);
		char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

		if (!nb_frags++)
			swap_mac_addresses(pkt);

		hex_dump(pkt, len, addr);

		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++);

		tx_desc->options = eop ? 0 : XDP_PKT_CONTD;
		tx_desc->addr = orig;
		tx_desc->len = len;

		if (eop) {
			frags_done += nb_frags;
			nb_frags = 0;
			eop_cnt++;
		}
	}

	xsk_ring_prod__submit(&xsk->tx, frags_done);
	xsk_ring_cons__release(&xsk->rx, frags_done);

	xsk->ring_stats.rx_npkts += eop_cnt;
	xsk->ring_stats.tx_npkts += eop_cnt;
	xsk->ring_stats.rx_frags += rcvd;
	xsk->ring_stats.tx_frags += rcvd;
	xsk->outstanding_tx += frags_done;
}

static void l2fwd_all(void)
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
			l2fwd(xsks[i]);

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
	if (opt_bench == BENCH_L2FWD) {
		rx = true;
		xsk_populate_fill_ring(umem);
	}
	if (opt_bench == BENCH_L2FWD )
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


	l2fwd_all();

out:
	benchmark_done = true;

	if (!opt_quiet)
		pthread_join(pt, NULL);

	xdpsock_cleanup();

	munmap(bufs, NUM_FRAMES * opt_xsk_frame_size);

	return 0;
}
