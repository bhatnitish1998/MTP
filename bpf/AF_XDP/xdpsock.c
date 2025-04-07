/*
Applications
0 = NAT (Reads and modifies the header)
1 = IDS (DPI Reads entire packet and checks if it matches a pattern)
2 = Decryption proxy (Reads the data and writes decrypted data)
3 = L2 forward (MACSWAP and transmit)
4 = Key value store (GET (send back value) and STORE requests (send back aknowledgement)) 
*/

/*
Parameters to count
1. Throughput (Data / lastpacket time - first packet time)
2. Latency  (pktgen)
3. L2 miss rate (perf)
4. LLC miss rate (perf)
5. Cold count (based on consumer producer movement)
*/

#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
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
#include <netinet/ip.h> 
#include <assert.h>

// userspace xdp library
#include "../lib/xdp-tools/headers/xdp/xsk.h"

// real applications
#include "./ported-mica/hash.h"
#include "./ported-mica/mehcached.h"
#include "./maglev/hashmap.h"
#include "./maglev/load_balancer.h"


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

#define SCHED_PRI__DEFAULT	0
#define STRERR_BUFSIZE          1024

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;

// xdp variables
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
static unsigned long prev_time;
timer_t timerid_monitor;

////////////// Application variables  ////////////////
int opt_application_type = 0;

// NAT
const char *nat_ip = "203.0.113.5";
uint16_t nat_port = 12345;

// IDS
const char *signature = "x7GmQ2ZpLt9vA5KfYcJ3oBNwHTdzRl1PbCyVX8sM6OqUWg4E0DrhFjkLaSnmtiIue\
YvBZxGpTLoK3f5NAJ9M2QzRd1PbCyVwHX8m67UqWgOE04DJFhrSLkManItieuCXYV\
GmTzLQ9pK35oJfNA2BRd1PbCyVXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzL\
Q9pK35oJfNA2BRd1PbCyVXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzLQ9pK3\
5oJfNA2BRd1PbCyVXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzLQ9pK35oJfN\
A2BRd1PbCyVXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzLQ9pK35oJfNA2BRd\
1PbCyVXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzLQ9pK35oJfNA2BRd1PbCy\
VXwH8M67UqWgOEDJ04hrSLkManItieuCXYVGmTzLQ9pK35oJfNA2BRd1PbCyVXwH8\
M67UqWgOEDJ04hrSLkManItieuCXYV";

// DP 
int decryption_key =3;

// MICA
struct mehcached_table table_o;
struct mehcached_table *table;

#define NUM_KEYS 2000
#define VALUE_SIZE 256

size_t default_keys [NUM_KEYS];
int keys_index = 0;
char default_value [VALUE_SIZE];

bool flag = false;

// Maglev

char bkd_addr[MAX_BACKENDS][INET_ADDRSTRLEN];
int nbackends = 3;

struct hashmap services;
struct hashmap backends;
struct hashmap maglev_tables;

struct hashmap active_sessions;

///////////////// Throughput computation ///////////////
struct timespec start, end;
long long throughput_packets = 100000000;


///////////////// Burst ///////////////////////////
static bool opt_burst_tp = false;
static const char *burst_tp_file = "";
char burst_tp_file_path[256];
#define INTERVAL_NS 10000000  // 10ms 
#define MAX_BURST_TP_COUNT 3000
static int burst_tp_count = 0;
static unsigned long prev_tp = 0;

struct burst_tp_info {
	unsigned long interval;
	u32 throughput;
	u32 cdf_tp;
};

struct burst_tp_info burst_tp_array[MAX_BURST_TP_COUNT];

struct timespec start_time_burst, current_time_burst;
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
static u32 opt_batch_size = 512;

// Address multiplier
static int multiplier = 4096;
static int opt_packet_size = 512;

static bool opt_complete_umem;
static bool opt_spf = false;
static bool opt_count_cold = false;


////////////// Packet related variables //////////////

static int dummy_count;
static long long pkt_count = 0;

/////////////// Warm buffers & addresses  ////////////
static bool opt_warm_buffers = false;

static long long warm_count;
static long long cold_count;
static long long prev_prod = 16384;
static long long prev_cons = 0;
static long long prod_extra = 0;
struct addr_info{
	u32 number;
	u64 addr;
	u32 len;
};

static int to_add =-1;
u64 prev_consumer =0;

////////////////////////////////////////

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
////////////////////////////////////////////////////////

// Load balancer
// vaddr,vport,proto
struct service_entry {
	struct service_id key;
	struct service_info value;
};
// Bkd adr, port, IFindex, ifname
struct backend_entry {
	struct backend_id key;
	struct backend_info value;
};

static void configure(struct maglev *mag, int num_bkds)
{
	int *bkd_mapping = mag->bkd_mapping;
	int next[num_bkds];
	// populate each bkd first
	int permutation[num_bkds][MAGLEV_LOOKUP_SIZE];
	for (int i = 0; i < num_bkds; i++) {
		int hashval = murmurhash(&i, sizeof(int), 0);
		int offset = hashval % MAGLEV_LOOKUP_SIZE;
		int skip = hashval % (MAGLEV_LOOKUP_SIZE - 1) + 1;
		for (int j = 0; j < MAGLEV_LOOKUP_SIZE; j++) {
			permutation[i][j] = (((offset + j * skip) % MAGLEV_LOOKUP_SIZE) + MAGLEV_LOOKUP_SIZE) % MAGLEV_LOOKUP_SIZE;
		}
	}

	for (int i = 0; i < num_bkds; i++) {
		next[i] = 0;
	}

	for (int i = 0; i < MAGLEV_LOOKUP_SIZE; i++) {
		bkd_mapping[i] = -1;
	}

	uint32_t filled = 0;
	while (1) {
		for (int i = 0; i < num_bkds; i++) {
			if (next[i] >= MAGLEV_LOOKUP_SIZE)
				continue;
			int c = permutation[i][next[i]];
			while (bkd_mapping[c] >= 0) {
				next[i]++;
				if (next[i] >= MAGLEV_LOOKUP_SIZE) {
					break;
				}
				c = permutation[i][next[i]];
			}
			bkd_mapping[c] = i;
			next[i]++;
			filled++;
			if (filled == MAGLEV_LOOKUP_SIZE) {
				return;
			}
		}
		bool end = true;
		for (int i = 0; i < num_bkds; i++) {
			if (next[i] < MAGLEV_LOOKUP_SIZE) {
				end = false;
				break;
			}
		}
		if (end) {
			break;
		}
	}

	int bkd = 0;
	int bkd1 = 0, bkd2 = 0;
	for (int i = 0; i < MAGLEV_LOOKUP_SIZE; i++) {
		if (bkd_mapping[i] < 0) {
			bkd_mapping[i] = bkd;
			bkd++;
			bkd %= num_bkds;
		}
		if (bkd_mapping[i] == 0)
			bkd1++;
		else
			bkd2++;
	}
}


static void load_services(void)
{
	char *service_ip = "10.129.2.131"; 

	unsigned int base_ip[4] = {192, 192, 192, 0};

    for (int i = 0; i < MAX_BACKENDS; i++) {
        snprintf(bkd_addr[i], INET_ADDRSTRLEN, "%u.%u.%u.%u",
                 base_ip[0], base_ip[1], base_ip[2], base_ip[3] + i);
    }


	char proto[4];
	unsigned srv_port, bkd_port;
	uint8_t mac_addr[6];
	struct service_info *srv_info;
	struct backend_entry *bkd_entry;
	struct in_addr addr;
	int nservices = 1, service_first_free = 0;
	int *srvindex;
	struct service_entry *service_entries;
	struct backend_entry *backend_entries;
	struct hashmap srv_to_index;

	hashmap_init(&services, sizeof(struct service_id), sizeof(struct service_info), MAX_SERVICES);
	hashmap_init(&backends, sizeof(struct backend_id), sizeof(struct backend_info), MAX_BACKENDS);
	hashmap_init(&maglev_tables, sizeof(struct service_id), sizeof(struct maglev), MAX_SERVICES);

	service_entries = malloc(sizeof(struct service_entry) * nservices);
	backend_entries = malloc(sizeof(struct backend_entry) * nbackends);
	hashmap_init(&srv_to_index, sizeof(struct service_id), sizeof(int), nservices);

	mac_addr[0] = 0x11;
	mac_addr[1] = 0x22;
	mac_addr[2] = 0x33;
	mac_addr[3] = 0x44;
	mac_addr[4] = 0x55;
	mac_addr[5] = 0x66;
	// Manually add services and backends
	// Service 1: UDP from 192.168.1.1:80 to backend 192.168.1.2:8080
	// strcpy(srv_addr, "192.168.1.1"); Stored from main fn itself
	srv_port = 80;
	bkd_port = 8080;
	strcpy(proto, "UDP");
	for (int index = 0; index < nbackends; index++) {
		bkd_entry = &backend_entries[index];
		inet_aton(service_ip, &addr);
		bkd_entry->key.service.vaddr = addr.s_addr;
		bkd_entry->key.service.vport = htons(srv_port);
		bkd_entry->key.service.proto = IPPROTO_UDP;

		inet_aton(bkd_addr[index], &addr);
		bkd_entry->value.addr = addr.s_addr;
		bkd_entry->value.port = htons(bkd_port);
		__builtin_memcpy(&bkd_entry->value.mac_addr, mac_addr, sizeof(mac_addr));

		srvindex = hashmap_lookup_elem(&srv_to_index, &bkd_entry->key.service);
		if (!srvindex) {
			struct service_entry *srv_entry = &service_entries[service_first_free];
			srv_entry->key = bkd_entry->key.service;
			srv_entry->value.backends = 0;
			srv_info = &srv_entry->value;

			if (hashmap_insert_elem(&srv_to_index, &srv_entry->key, &service_first_free) != 1) {
				fprintf(stderr, "ERROR: unable to add service index to hash map\n");
				exit(EXIT_FAILURE);
			}

			service_first_free++;
		} else {
			srv_info = &service_entries[*srvindex].value;
		}

		bkd_entry->key.index = srv_info->backends;
		srv_info->backends++;
	}

	for (int i = 0; i < nservices; i++) {
		// printf("%u, %u\n", service_entries[i].key.vaddr, (__u32)(service_entries[i].key.vport));
		if (hashmap_insert_elem(&services, &service_entries[i].key, &service_entries[i].value) != 1) {
			fprintf(stderr, "ERROR: unable to add service to hash map\n");
			exit(EXIT_FAILURE);
		}
	}

	for (int i = 0; i < nbackends; i++) {
		if (hashmap_insert_elem(&backends, &backend_entries[i].key, &backend_entries[i].value) != 1) {
			fprintf(stderr, "ERROR: unable to add backend to hash map\n");
			exit(EXIT_FAILURE);
		}
	}

	// Setting up lookup tables for nservices
	for (int i = 0; i < nservices; i++) {
		struct maglev *lookup = malloc(sizeof(struct maglev));
		uint32_t num_bkds = service_entries[i].value.backends;
		configure(lookup, num_bkds);
		if (hashmap_insert_elem(&maglev_tables, &service_entries[i].key, lookup) != 1) {
			fprintf(stderr, "ERROR: unable to add maglev table to hash map\n");
			exit(EXIT_FAILURE);
		}
	}

	printf("Added %u services and %u backends\n", nservices, nbackends);

	free(service_entries);
	free(backend_entries);
	hashmap_free(&srv_to_index);

	return;
}

////////////////////////////////////////////////////////

static void inline prefetch_packet(void* addr)
{
	char *pkt = (char*)addr;
	__builtin_prefetch(&pkt[0],1,3);

	if(opt_application_type == 4 ){
		for(int i =1; i<= VALUE_SIZE; i+=64)
		{	
			__builtin_prefetch(&pkt[i],1,3);
		}
	}

	else if(opt_application_type == 2)
	{
		for(int i =1; i< opt_packet_size; i+=64)
		{	
			__builtin_prefetch(&pkt[i],1,3);
		}

	}
}

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

static void burst_tp_print() {

	u32 pkt_sum = 0;
	FILE *file = fopen(burst_tp_file_path, "a");
	if (file == NULL) {
		perror("Error opening file");
	}

	fprintf(file, "i \t interval \t throughput \t cdf_tp\n");
	//print each buffer addresse usage count
	for(int i = 0; i < MAX_BURST_TP_COUNT; i++)
	{
		fprintf(file, "%d \t %ld \t %d \t %d\n", i, burst_tp_array[i].interval, burst_tp_array[i].throughput, burst_tp_array[i].cdf_tp);
		pkt_sum += burst_tp_array[i].throughput;
	}
	fprintf(file, "Total num of packets recieved:%d\n", pkt_sum);

	fclose(file);
}


void post_exp_process()
{

	long long diff_sec = end.tv_sec - start.tv_sec;
    long long diff_nsec = end.tv_nsec - start.tv_nsec;

	if (diff_nsec < 0) {
        diff_sec -= 1;
        diff_nsec += 1000000000L;
    }
    long long elapsed_ms = (diff_sec * 1000000000 + diff_nsec)/1000000;

	FILE *file = fopen("./logs/stats.csv", "w");
	if (file == NULL) {
		perror("Error opening file");
	}
	for (int i = 0; i < num_socks && xsks[i]; i++) {
		if (!xsk_get_xdp_stats(xsk_socket__fd(xsks[i]->xsk), xsks[i])){
			fprintf(file, "rx_packets,%lld\n",pkt_count);
			fprintf(file, "rx_dropped,%lu\n",xsks[i]->ring_stats.rx_dropped_npkts);
			fprintf(file, "rx_invalid,%lu\n",xsks[i]->ring_stats.rx_invalid_npkts);
			fprintf(file, "rx_queue_full,%lu\n",xsks[i]->ring_stats.rx_full_npkts);
			fprintf(file, "fill_ring_empty,%lu\n",xsks[i]->ring_stats.rx_fill_empty_npkts);
			fprintf(file, "100M packets_time_in_ms,%lld\n",elapsed_ms);
			// Warm buffer count
			fprintf(file, "warm_count,%lld\n",warm_count);
			fprintf(file, "cold_count,%lld\n",cold_count);
			// Write dummy count to avoid compiler optimization
			fprintf(file, "dummy_count,%d\n",dummy_count);
		}
	}

	fclose(file);

	if(opt_application_type == 4)
	{
		mehcached_table_free(table);
	}

	if(opt_burst_tp)
		burst_tp_print();

	if(opt_application_type ==5)
		hashmap_free(&active_sessions);
}


static void inline process_packet_maglev(void *data, size_t length, u64 addr)
{

	struct ether_header *eth = (struct ether_header *)data;
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ether_header));
    int ip_header_len = ip->ihl * 4;
	struct udphdr *udp = (struct udphdr *)(data + sizeof(struct ether_header) + ip_header_len);


	struct session_id sid = { 0 };
	sid.saddr = ip->saddr;
	sid.daddr = inet_addr("10.129.2.131");
	sid.proto = ip->protocol;
	sid.sport = udp->source;
	sid.dport = htons(80);


	/* Look for known sessions */
	struct replace_info *rep = hashmap_lookup_elem(&active_sessions, &sid);
	if (rep) {
		return;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = { .vaddr =sid.daddr, .vport = sid.dport, .proto = ip->protocol };
	struct service_info *srvinfo = hashmap_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		printf("ERROR: missing service --> DROPPING\n");
		return;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = ((struct maglev *)hashmap_lookup_elem(&maglev_tables, &srvid))
				 ->bkd_mapping[murmurhash(&sid, sizeof(struct session_id), 0) % MAGLEV_LOOKUP_SIZE]
	};
	struct backend_info *bkdinfo = hashmap_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		printf("ERROR: missing backend --> DROPPING\n");
		return;
	}

	/* Store the forward session */
	struct replace_info fwd_rep;
	fwd_rep.dir = DIR_TO_BACKEND;
	fwd_rep.addr = bkdinfo->addr;
	fwd_rep.port = bkdinfo->port;
	fwd_rep.bkdindex = bkdid.index;
	__builtin_memcpy(fwd_rep.mac_addr, &bkdinfo->mac_addr, sizeof(fwd_rep.mac_addr));
	rep = &fwd_rep;
	if (hashmap_insert_elem(&active_sessions, &sid, &fwd_rep) != 1) {
		fprintf(stderr, "ERROR: unable to add forward session to map\n");
		return;
	}

	/* Store the backward session */
	struct replace_info bwd_rep;
	bwd_rep.dir = DIR_TO_CLIENT;
	bwd_rep.addr = srvid.vaddr;
	bwd_rep.port = srvid.vport;
	__builtin_memcpy(&bwd_rep.mac_addr, eth->ether_shost, sizeof(eth->ether_shost));
	sid.daddr = sid.saddr;
	sid.dport = sid.sport;
	sid.saddr = bkdinfo->addr;
	sid.sport = bkdinfo->port;
	if (hashmap_insert_elem(&active_sessions, &sid, &bwd_rep) != 1) {
		fprintf(stderr, "ERROR: unable to add backward session to map\n");
		return;
	}

}



static void inline process_packet_nat(void *data, size_t length, u64 addr)
{
	// parse headers
	struct ether_header *eth = (struct ether_header *)data;
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ether_header));
    int ip_header_len = ip->ihl * 4;
	struct udphdr *udp = (struct udphdr *)(data + sizeof(struct ether_header) + ip_header_len);

    // Change IP and port (Assuming SNAT;)
    ip->saddr = inet_addr(nat_ip);
    udp->source = htons(nat_port);
}


static void inline process_packet_ids(void *data, size_t length, u64 addr)
{
	if(memcmp(data, signature, length) == 0)
		dummy_count++;
	else
		dummy_count--;
}

static void inline process_packet_decryption(void *data, size_t length, u64 addr)
{

	struct ether_header *eth = (struct ether_header *)data;
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ether_header));
    int ip_header_len = ip->ihl * 4;
    struct udphdr *udp = (struct udphdr *)(data + sizeof(struct ether_header) + ip_header_len);
    unsigned char *payload = (unsigned char *)(udp + 1);
    int udp_length = ntohs(udp->len);
    int payload_len = udp_length - sizeof(struct udphdr);

	
	for(int i =0; i< payload_len; i++)
		payload[i] = payload[i] + decryption_key;

}

static void inline process_packet_l2fwd(void *data, size_t length, u64 addr)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr tmp;

	tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = tmp;
}

static void inline process_packet_mica (void *data, size_t length, u64 addr)
{
	struct ether_header *eth = (struct ether_header *)data;
	struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ether_header));
	int ip_header_len = ip->ihl * 4;
	struct udphdr *udp = (struct udphdr *)(data + sizeof(struct ether_header) + ip_header_len);
	unsigned char *payload = (unsigned char *)(udp + 1);
	int udp_length = ntohs(udp->len);
	int payload_len = udp_length - sizeof(struct udphdr);
	
	size_t key;
	char value[256];
	
	// get key
	memcpy(&key, payload, sizeof(size_t));
	flag = !flag;
	key = default_keys[keys_index];
	keys_index = (keys_index+1) % NUM_KEYS;

	// GET 
	if(flag)
	{
		uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
		size_t value_length = sizeof(value);

		if (mehcached_get(0, table, key_hash, (const uint8_t *)&key, sizeof(key), (uint8_t *)&value, &value_length, NULL, false))
			assert(value_length == sizeof(value));

		// send value
		memcpy(payload + sizeof(size_t), &value, 256);
	}
	
	// STORE 
	else 
	{
		memcpy(value, payload + sizeof(size_t), 256);
		value[255] = '\0';
		uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
		if (!mehcached_set(0, table, key_hash, (const uint8_t *)&key, sizeof(key), (const uint8_t *)&value, sizeof(value), 0, true))
			assert(false);

		// send acknowledgement
		memcpy(payload + sizeof(size_t),&value, 256);
		
	}
}

static void inline process_packet(void *data, size_t length, u64 addr)
{
	if(pkt_count == 0)
	{
		if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
			perror("clock_gettime");
			return;
		}
	}
	// 100 million packets
	else if(pkt_count == throughput_packets)
	{
		if (clock_gettime(CLOCK_MONOTONIC, &end) == -1) {
			perror("clock_gettime");
			return;
		}
	}

	pkt_count++;

	if(opt_application_type == 0)
		process_packet_nat(data,length,addr);

	else if( opt_application_type == 1)
		process_packet_ids(data,length,addr);

	else if( opt_application_type == 2)
		process_packet_decryption(data,length,addr);

	else if( opt_application_type == 3)
		process_packet_l2fwd(data,length,addr);

	else if(opt_application_type == 4)
		process_packet_mica(data,length,addr);

	else if(opt_application_type == 5)
		process_packet_maglev(data,length,addr);

}


#define ETH_FCS_SIZE 4

static struct xsk_umem_info *xsk_configure_umem(void *buffer, u64 size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
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
	{"app-type", required_argument, 0, 'A'},
	{"count-cold", no_argument, 0, 'X'},
	{"burst-tp", required_argument, 0, 'E'},
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
		"  -A, --app-type=type	Application type(0,1,2,3,4,5) \n"
		"  -X, --count-cold   Count cold buffers \n"
		"  -E, --burst-tp=file	Write per 100ms throughput to the given file \n"
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
				"i:q:pSNn:w:O:czf:muMd:b:BU:hWs:CPA:XE:",
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
		case 'A':
			opt_application_type = atoi(optarg);
			if(opt_application_type == 0)
				printf("NAT application\n");
			else if(opt_application_type == 1)
				printf("IDS application\n");
			else if(opt_application_type == 2)
				printf("Decryption proxy application\n");
			else if(opt_application_type == 3)
				printf("L2FWD application\n");
			else if(opt_application_type == 4)
				printf("MICA application \n");
			else if(opt_application_type == 5)
				printf("Maglev application \n");
			break;
		case 'X':
			opt_count_cold = 1;
			break;
		case 'E':
			opt_burst_tp = 1;
			burst_tp_file = optarg;
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


	if(opt_burst_tp && burst_tp_count < MAX_BURST_TP_COUNT){
		clock_gettime(opt_clock, &current_time_burst);
		u64 elapsed_time = (current_time_burst.tv_sec - start_time_burst.tv_sec) * 1e9 + 
                          (current_time_burst.tv_nsec - start_time_burst.tv_nsec);
		if(elapsed_time >= INTERVAL_NS) {
			// printf("elapsed_time: %llu\n", elapsed_time);
			burst_tp_array[burst_tp_count].interval = elapsed_time;
			u32 curr_tp = xsk->ring_stats.rx_npkts;
			u32 tp = curr_tp - prev_tp;
			burst_tp_array[burst_tp_count].throughput = tp;
			burst_tp_array[burst_tp_count].cdf_tp = curr_tp;
			burst_tp_count++;
			prev_tp = curr_tp;
			clock_gettime(opt_clock, &start_time_burst);
		}		
	}

	if(opt_count_cold)
	{
		if( prev_cons != *xsk->umem->fq.consumer)
		{
			int cons_move = *xsk->umem->fq.consumer - prev_cons;
			int prod_move = *xsk->umem->fq.producer - prev_prod;
			prev_cons = *xsk->umem->fq.consumer; 
			prev_prod = *xsk->umem->fq.producer;

			if(cons_move > prod_move + prod_extra)
			{
				cold_count += cons_move - (prod_move + prod_extra);
				warm_count += prod_move + prod_extra;
				prod_extra =0;
			}

			else if( cons_move > prod_move)
			{
				warm_count += cons_move;
				prod_extra -= (cons_move - prod_move);
			}

			else	
			{
				warm_count += cons_move;
				prod_extra += (prod_move-cons_move);
			}
		}
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

	if(opt_burst_tp && burst_tp_count < MAX_BURST_TP_COUNT){
		clock_gettime(opt_clock, &current_time_burst);
		u64 elapsed_time = (current_time_burst.tv_sec - start_time_burst.tv_sec) * 1e9 + 
                          (current_time_burst.tv_nsec - start_time_burst.tv_nsec);
		if(elapsed_time >= INTERVAL_NS) {
			// printf("elapsed_time: %llu\n", elapsed_time);
			burst_tp_array[burst_tp_count].interval = elapsed_time;
			u32 curr_tp = xsk->ring_stats.rx_npkts;
			u32 tp = curr_tp - prev_tp;
			burst_tp_array[burst_tp_count].throughput = tp;
			burst_tp_array[burst_tp_count].cdf_tp = curr_tp;
			burst_tp_count++;
			prev_tp = curr_tp;
			clock_gettime(opt_clock, &start_time_burst);
		}		
	}


	if(opt_count_cold)
	{
		int cons_move;
		int prod_move;
		if( prev_cons != *xsk->umem->fq.consumer)
		{
			cons_move = *xsk->umem->fq.consumer - prev_cons;
			prod_move = *xsk->umem->fq.producer - prev_prod;
			prev_cons = *xsk->umem->fq.consumer; 
			prev_prod = *xsk->umem->fq.producer;

			if(cons_move > prod_move + prod_extra)
			{
				cold_count += cons_move - (prod_move + prod_extra);
				warm_count += prod_move + prod_extra;
				prod_extra =0;
			}

			else if( cons_move > prod_move)
			{
				warm_count += cons_move;
				prod_extra -= (cons_move - prod_move);
			}

			else	
			{
				warm_count += cons_move;
				prod_extra += (prod_move-cons_move);
			}
		}

		// printf("cons_move : %lld prod_move : %lld prod_extra : %lld warm_count : %lld cold_count : %lld\n", cons_move, prod_move, prod_extra, warm_count, cold_count);
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
			if(opt_application_type == 3 || opt_application_type == 4)
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


	srand(614);

	if(opt_application_type == 5)
	{
		load_services();
		hashmap_init(&active_sessions, sizeof(struct session_id), sizeof(struct replace_info), MAX_SESSIONS);
	}

	if(opt_application_type ==4)
	{
		const size_t page_size = 1048576 * 2;
		const size_t num_numa_nodes = 1;
		const size_t num_pages_to_try = 16384;
		const size_t num_pages_to_reserve = 16384 - 2048; 
		size_t alloc_overhead = sizeof(struct mehcached_item);
		
		mehcached_shm_init(page_size, num_numa_nodes, num_pages_to_try, num_pages_to_reserve);
		
		table = &table_o;
		size_t numa_nodes[] = {(size_t)-1};
		// mehcached_table_init(table, 1, 1, 256, false, false, false, numa_nodes[0], numa_nodes, MEHCACHED_MTH_THRESHOLD_FIFO);
		mehcached_table_init(table, (NUM_KEYS + MEHCACHED_ITEMS_PER_BUCKET - 1) / MEHCACHED_ITEMS_PER_BUCKET, 1, NUM_KEYS * /*MEHCACHED_ROUNDUP64*/(alloc_overhead + 8 + 8), false, false, false, numa_nodes[0], numa_nodes, MEHCACHED_MTH_THRESHOLD_FIFO);
		assert(table);


		memset(default_value, 'A', 255);
    	default_value[255] = '\0'; 

		for(size_t i =0; i< NUM_KEYS; i++)
		{
			size_t key = i; 
			default_keys [i] = key;

			uint64_t key_hash = hash((const uint8_t *)&key, sizeof(key));
			if (!mehcached_set(0, table, key_hash, (const uint8_t *)&key, sizeof(key), (const uint8_t *)&default_value, sizeof(default_value), 0, false))
				assert(false);
		}
	}

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

	if(opt_burst_tp)
	{
		snprintf(burst_tp_file_path, sizeof(burst_tp_file_path), "./logs/%s", burst_tp_file);
		FILE *file = fopen(burst_tp_file_path, "w");
		if (file == NULL) {
			perror("Error opening file");
		}
		fclose(file);

		clock_gettime(opt_clock, &start_time_burst);
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
	if(opt_application_type == 3 || opt_application_type == 4)
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
