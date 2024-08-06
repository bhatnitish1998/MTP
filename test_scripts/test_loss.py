import os
import subprocess
import time
import csv

curdir = os.path.dirname(__file__)

TESTER = 'preeti@10.129.2.253'
IFNAME = 'ens261f1'

MOONGEN_PATH = '~/nitish/MoonGen/build/MoonGen'
PKTGEN_SCRIPT_PATH = '~/nitish/MoonGen/examples/preeti/check.lua'

APP_NAME = 'xdpsock'
APP_PATH = f'/home/preeti/nitish/MTP/bpf/AF_XDP/{APP_NAME}'

LATENCY_FILENAME = 'latency_results.csv'
CACHE_FILENAME = 'cache_results.csv'
TP_FILENAME = 'tp_results.csv'

EXP_TIME = 30

PERF_COUNTERS = ['LLC-loads', 'LLC-load-misses', 'LLC-stores', 'LLC-store-misses',
                 'L1-dcache-loads', 'L1-dcache-load-misses', 'L1-dcache-stores', 'L1-icache-misses',
                 'l2_rqsts.references', 'l2_rqsts.miss', 'l2_rqsts.all_pf', 'l2_rqsts.l2_pf_hit', 'l2_rqsts.l2_pf_miss',
                 'instructions']




def change_ddio(value):
    cmd = ['sudo', '/home/preeti/nitish/MTP/ddio/change-ddio', str(value)]
    ret = subprocess.run(cmd)


def change_prefetch(value):
    if (value):
        cmd = ['sudo', 'wrmsr', '0x1a4', '-a', '0']
        ret = subprocess.run(cmd)
    else:
        cmd = ['sudo', 'wrmsr', '0x1a4', '-a', '15']
        ret = subprocess.run(cmd)


def set_interrupts_core():
    command = "echo 1 > /proc/irq/105/smp_affinity"
    subprocess.run(['sudo', 'bash', '-c', command], check=True)


def kill_process():
    cmd = ['pidof', APP_NAME]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    cmd = ['sudo', 'kill', '-SIGINT', str(int(ret.stdout))]
    ret = subprocess.run(cmd)
    time.sleep(3)


def get_rcvd_pkts():
    with open("./logs/stats.csv", mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)
    value = rows[0][1]
    return int(value)


def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:./tmp.csv', '.']
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open("tmp.csv", "r") as f:
        ret = f.read().splitlines()[1].split(';')
    return ret[0], int(ret[1])


def get_latency_data():
    with open('./logs/latency_data.txt', 'r') as file:
        data = file.read()
    values = data.split(',')
    values = [float(value) if '.' in value else int(value) for value in values]
    return values


def write_row_to_files(row):
    with open(TP_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)

    with open(LATENCY_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)

    with open(CACHE_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)


def write_row_to_file(filename, row):
    with open(filename, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)


# mode 0 = throughput       pattern 0 = sequential
# mode 1 = cache            pattern 1 = random
# mode 2 = latency
def run_once(exp_cmd, mode, pattern, curr_t):
    curr_cmd = exp_cmd.copy()

    if mode == 2:
        curr_cmd.append('-L')

    print(curr_cmd)

    rx_queue_full = -1
    row = []

    #start
    flushllc = subprocess.run(['/home/preeti/nitish/cache/flush'], capture_output=True, text=True)
    set_interrupts_core()
    app = subprocess.Popen(curr_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ['ssh', TESTER, 'sudo', 'taskset', '-c', '0-11', MOONGEN_PATH, PKTGEN_SCRIPT_PATH, '0', '0', '-c', '1', '-o',
           'tmp.csv', '-s', str(PKT_SIZE), '-r', str(curr_t), '-t', str(EXP_TIME)]
    pktgen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(7)

    if mode == 1:
        cmd = ['pidof', APP_NAME]
        pid = subprocess.run(cmd, capture_output=True, text=True)
        perf = ['sudo', 'perf', 'stat', '--no-big-num', '-e', ','.join(PERF_COUNTERS), '-p', str(int(pid.stdout))]
        perf_res = subprocess.Popen(perf, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    pktgen.wait()
    kill_process()
    rate, tx_pkts = get_pktgen_stats()
    rx_pkts = get_rcvd_pkts()
    loss = (tx_pkts - rx_pkts) / tx_pkts

    #Get stats
    with open("./logs/stats.csv", mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    rx_dropped = rows[1][1]
    rx_invalid = rows[2][1]
    rx_queue_full = rows[3][1]
    rx_fill_ring_empty = rows[4][1]
    out_of_order = rows[5][1]

    print(f'Target {curr_t} Mbps, loss {loss * 100:.2f}%\n')

    formatted_loss = f"{loss * 100:.3f}"

    if mode == 2:
        # Parse Latency statistics
        latency_values = get_latency_data()
        count_latency = latency_values[0]
        min_latency = latency_values[1]
        max_latency = latency_values[2]
        avg_latency = latency_values[3]
        tail99_latency = latency_values[4]
        tail999_latency = latency_values[5]

        row = [" ", tx_pkts, rx_pkts, formatted_loss, curr_t, rate, rx_dropped, rx_invalid, rx_queue_full,
               rx_fill_ring_empty, out_of_order, count_latency, min_latency, max_latency, avg_latency, tail99_latency,
               tail999_latency]

    if mode == 1:
        # Parse cache statistics
        ret = perf_res.stderr.read()
        reslines = ret.splitlines()
        LLC_loads = int(reslines[3].split()[0])
        LLC_load_misses = int(reslines[4].split()[0])
        LLC_stores = int(reslines[5].split()[0])
        LLC_store_misses = int(reslines[6].split()[0])
        L1_dcache_loads = int(reslines[7].split()[0])
        L1_dcache_load_misses = int(reslines[8].split()[0])
        L1_dcache_stores = int(reslines[9].split()[0])
        L1_icache_misses = int(reslines[10].split()[0])
        l2_rqsts_references = int(reslines[11].split()[0])
        l2_rqsts_miss = int(reslines[12].split()[0])
        l2_rqsts_all_pf = int(reslines[13].split()[0])
        l2_rqsts_l2_pf_hit = int(reslines[14].split()[0])
        l2_rqsts_l2_pf_miss = int(reslines[15].split()[0])
        instructions = int(reslines[16].split()[0])

        LLC_load_miss_percent = f"{(LLC_load_misses / LLC_loads) * 100:.4f}"
        LLC_store_miss_percent = f"{(LLC_store_misses / LLC_stores) * 100:.4f}"
        L1_dcache_load_miss_percent = f"{(L1_dcache_load_misses / L1_dcache_loads) * 100:.4f}"
        L2_miss_percent = f"{(l2_rqsts_miss / l2_rqsts_references) * 100:.4f}"

        if l2_rqsts_all_pf == 0:
            L2_pf_hit_percent = 0
            L2_pf_miss_percent = 0
        else:
            L2_pf_hit_percent = f"{(l2_rqsts_l2_pf_hit / l2_rqsts_all_pf) * 100:.4f}"
            L2_pf_miss_percent = f"{(l2_rqsts_l2_pf_miss / l2_rqsts_all_pf) * 100:.4f}"

        row = [" ", tx_pkts, rx_pkts, formatted_loss, curr_t, rate, rx_dropped, rx_invalid, rx_queue_full,
               rx_fill_ring_empty, out_of_order, LLC_loads, LLC_load_misses, LLC_stores, LLC_store_misses,
               L1_dcache_loads, L1_dcache_load_misses, L1_dcache_stores, L1_icache_misses, l2_rqsts_references,
               l2_rqsts_miss, l2_rqsts_all_pf, l2_rqsts_l2_pf_hit, l2_rqsts_l2_pf_miss, instructions,
               LLC_load_miss_percent, LLC_store_miss_percent, L1_dcache_load_miss_percent, L2_miss_percent,
               L2_pf_hit_percent, L2_pf_miss_percent]
        write_row_to_file(CACHE_FILENAME,row)

    if mode == 0:
        row = [" ", curr_t]

    return loss, row


def run_till_zero(exp_cmd, mode, pattern):
    curr_t = MAX_TARGET

    while True:
        loss, row = run_once(exp_cmd, mode, pattern, curr_t)
        if loss < 0.001:
            curr_t = min(MAX_TARGET, curr_t + 500)
            break
        curr_t = curr_t - 500

    while True:
        loss, row = run_once(exp_cmd, mode, pattern, curr_t)
        if loss < 0.001:
            curr_t = min(MAX_TARGET, curr_t + 200)
            break
        curr_t = curr_t - 200

    while True:
        loss, row = run_once(exp_cmd, mode, pattern, curr_t)
        if loss < 0.001:
            return row
        curr_t = curr_t - 100


def run_all():
    for x in experiments:
        write_row_to_files(x)

        # throughput
        row = run_till_zero(x, 0, 0)
        write_row_to_file(TP_FILENAME, row)

        # cache
        row = run_till_zero(x, 1, 0)
        write_row_to_file(CACHE_FILENAME, row)


        # latency
        row = run_till_zero(x, 2, 0)
        write_row_to_file(LATENCY_FILENAME, row)



#########################################################

# Write header
# header = ["MODE", 'tx_pkts', 'rx_pkts', 'loss %', 'curr_t', 'rate', 'rx_dropped', 'rx_invalid', 'rx_queue_full',
#           'rx_fill_ring_empty', 'out_of_order', 'count_latency', 'min_latency', 'max_latency', 'avg_latency',
#           'tail99_latency', 'tail999_latency']
# write_row_to_file(LATENCY_FILENAME, header)

header = ["MODE", 'tx_pkts', 'rx_pkts', 'formatted_loss', 'curr_t', 'rate', 'rx_dropped', 'rx_invalid', 'rx_queue_full',
          'rx_fill_ring_empty', 'out_of_order', 'LLC_loads', 'LLC_load_misses', 'LLC_stores', 'LLC_store_misses',
          'L1_dcache_loads', 'L1_dcache_load_misses', 'L1_dcache_stores', 'L1_icache_misses', 'l2_rqsts_references',
          'l2_rqsts_miss', 'l2_rqsts_all_pf', 'l2_rqsts_l2_pf_hit', 'l2_rqsts_l2_pf_miss', 'instructions',
          'LLC_load_miss_percent', 'LLC_store_miss_percent', 'L1_dcache_load_miss_percent', 'L2_miss_percent',
          'L2_pf_hit_percent', 'L2_pf_miss_percent']
write_row_to_file(CACHE_FILENAME, header)

header = ["MODE", "Throughput"]
write_row_to_file(TP_FILENAME, header)

#########################
change_ddio(1)
change_prefetch(1)
#########################
PKT_SIZE = 512
MAX_TARGET = 17000

experiments = [
    # Write every cache line
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-B','-a'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-B','-a','-W'],

    # Interrupt mode
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-a'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-a','-W'],
]

run_all()



PKT_SIZE = 512
MAX_TARGET = 35000

experiments = [

    # Unaligned mode
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-B','-a','-u'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U', '16384','-B','-a','-u','-W'],

]

run_all()



PKT_SIZE = 512
MAX_TARGET = 38000

experiments=[
    # mac,first cache line
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B','-W'],
    ]

run_all()


PKT_SIZE = 256
MAX_TARGET = 10000

experiments = [

    # 256 B packet
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B','-s','256','-a'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B','-s','256','-a','-W'],
    ]


run_all()

PKT_SIZE = 64
MAX_TARGET = 6000

experiments = [

    # 64 B packet
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B','-s','64','-a'],
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-B','-s','64','-a','-W'],

    ]


run_all()


