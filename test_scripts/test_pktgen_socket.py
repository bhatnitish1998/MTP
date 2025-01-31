import os
import subprocess
import time
import pexpect
import csv

curdir = os.path.dirname(__file__)

TESTER = 'magnus@10.129.2.132'

IFNAME = 'ens19f0np0'

PKTGEN = '/home/magnus/packetgen/Pktgen-DPDK/builddir/app/pktgen'
PKTGEN_SCRIPT = '/home/magnus/nitish/MTP/pktgen_scripts/gen.lua' 
PKTGEN_STAT = '/home/magnus/nitish/MTP/pktgen_scripts/pkt_stat.txt'
LATENCY_STAT = '/home/magnus/nitish/MTP/pktgen_scripts/latency.txt'

APP_NAME = 'xdpsock'
APP_PATH = f'/home/magnus/nitish/MTP/bpf/AF_XDP/{APP_NAME}'

LATENCY_FILENAME = 'latency_results.csv'
CACHE_FILENAME = 'cache_results_new.csv'
TP_FILENAME = 'tp_results.csv'

EXP_TIME = 30

PERF_COUNTERS = ['L2_RQSTS.REFERENCES', 'L2_RQSTS.MISS', 'LONGEST_LAT_CACHE.REFERENCE', 'LONGEST_LAT_CACHE.MISS',
                 'INST_RETIRED.ANY', 'L2_LINES_IN.ALL', 'L2_LINES_OUT.NON_SILENT', 'L2_LINES_OUT.SILENT', 'L2_RQSTS.SWPF_HIT', 'L2_RQSTS.SWPF_MISS',  
                 'SW_PREFETCH_ACCESS.T0', 'SW_PREFETCH_ACCESS.T1_T2','L1-dcache-loads', 'L1-dcache-load-misses', 'L1-icache-load-misses','cycles','instructions'
                ]

MLC_ON = 0         
MLC_START_CORE = 3
LOSS = 0.001

######### Interrupt params
prev0 = 0
prev1 = 0

def defer_napi_irqs():
    command = 'echo 2 > /sys/class/net/ens19f0np0/napi_defer_hard_irqs'
    subprocess.run(['sudo', 'bash', '-c', command], check=True)

# interval in 100 micro
def set_gro_timeout():
    command = f'echo 200000 > /sys/class/net/ens19f0np0/gro_flush_timeout'
    subprocess.run(['sudo', 'bash', '-c', command], check=True)



# returns core 0 and core 1 interrupts
def get_interrupt_counts():
    global prev0
    global prev1
    cmd = "cat /proc/interrupts | grep ens19f0np0"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise Exception(f"Command failed: {result.stderr}")
    
    output = result.stdout.strip()
    parts = output.split()

    res0 = int (parts[1]) - prev0
    res1 = int(parts[2]) - prev1

    prev0 = int (parts[1])
    prev1 = int (parts[2])
    
    return res0,res1


# raises exception if ring size didnt change
def set_rx_ring_size(rx_size):
    try:
        command = f"sudo ethtool -G ens19f0np0 rx {rx_size}"
        subprocess.run(['sudo', 'bash', '-c', command], check=True)
    except:
        pass

# raises exception if ring size didnt change
def set_tx_ring_size(tx_size):
    try:
        command = f"sudo ethtool -G ens19f0np0 tx {tx_size}"
        subprocess.run(['sudo', 'bash', '-c', command], check=True)
    except:
        pass


def set_rss():
    cmd = f"ethtool -X ens19f0np0 start 0 equal 1"
    subprocess.run(['sudo', 'bash', '-c', cmd], check=True)


def kill_mlc():
    cmd = ['sudo', 'killall', '-SIGINT', 'mlc']
    ret = subprocess.run(cmd)

def start_mlc():
    cmd = [f'/home/magnus/nitish/MTP/MLC/mlc', '-c11', f'-k{MLC_START_CORE}-10', f'-t{EXP_TIME+15}']
    print(cmd)
    mlc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)


def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:{PKTGEN_STAT}', '.']
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    with open("pkt_stat.txt", "r") as f:
        ret = f.read().splitlines()
    return int(ret[0])


def change_ddio(value):
    cmd = ['sudo', '/home/magnus/nitish/MTP/ddio/change-ddio', str(value)]
    ret = subprocess.run(cmd)

# 1 = enable  0 = disable prefetch
def change_pfrefetch(value):
    if (value):
        cmd = ['sudo', 'wrmsr', '0x1a4', '-a', '32']
        ret = subprocess.run(cmd)
        cmd = ['sudo', 'wrmsr', '0x6d', '-a', '1073790976']
        ret = subprocess.run(cmd)
    else:
        cmd = ['sudo', 'wrmsr', '0x1a4', '-a', '47']
        ret = subprocess.run(cmd)
        cmd = ['sudo', 'wrmsr', '0x6d', '-a', '4399120302080']
        ret = subprocess.run(cmd)


def set_interrupts_core():
    # for i in range(144,192):
    for i in range(144,145):
        command = f"echo {INT_CORE} > /proc/irq/{i}/smp_affinity"
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


def get_latency_data():
    cmd = ['scp', f'{TESTER}:{LATENCY_STAT}', '.']
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    with open("latency.txt", "r") as f:
        ret = f.read().splitlines()
    return float(ret[0]),float(ret[1]),float(ret[2])



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



# mode 0 = throughput   
# mode 1 = cache    
# mode 2 = latency
def run_once(exp_cmd, mode, curr_t, pkt_size, duration, pktgen):
    curr_cmd = exp_cmd.copy()

    rx_queue_full = -1
    row = []

    # setup
    flushllc = subprocess.run(['/home/magnus/nitish/MTP/cache/flush'], capture_output=True, text=True)
    if MLC_ON:
        start_mlc()

    # start xdp
    app = subprocess.Popen(curr_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # configure pktgen
    pktgen.sendline(f'configure("{curr_t}","{pkt_size}")')
    pktgen.expect('config-done')

    # start pktgen
    if mode ==2:
        pktgen.sendline(f'run("{duration}","{1}")')
    else:
        pktgen.sendline(f'run("{duration}","{0}")')

    time.sleep(1)

    if mode == 1:
        cmd = ['pidof', APP_NAME]
        # cmd = ['pidof', 'mlc']
        pid = subprocess.run(cmd, capture_output=True, text=True)
        perf = ['sudo', 'perf', 'stat', '--no-big-num', '-e', ','.join(PERF_COUNTERS), '-p', str(int(pid.stdout))]
        perf_res = subprocess.Popen(perf, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    # wait for pktgen
    pktgen.expect('run-done',timeout = 120)
    time.sleep(1)
    # terminate processes
    kill_process()
    if MLC_ON:
        kill_mlc()
    
    # get loss
    tx_pkts = get_pktgen_stats()
    rx_pkts = get_rcvd_pkts()
    if tx_pkts != 0:
        loss = (tx_pkts - rx_pkts) / tx_pkts
    else:
        loss = 1

    #Get xdp stats
    with open("./logs/stats.csv", mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    rx_dropped = rows[1][1]
    rx_invalid = rows[2][1]
    rx_queue_full = rows[3][1]
    rx_fill_ring_empty = rows[4][1]
    out_of_order = rows[5][1]
    warm_count = rows [6][1]
    cold_count = rows [7][1]

    print(f'Target {curr_t} Gbps, loss {loss * 100:.2f}%\n')

    formatted_loss = f"{loss * 100:.3f}"

    if mode == 2:
        # Parse Latency statistics
        min_latency,max_latency,avg_latency = get_latency_data()


        row = [" ", tx_pkts, rx_pkts, formatted_loss, curr_t, rx_dropped, rx_invalid, rx_queue_full,
               rx_fill_ring_empty, out_of_order, min_latency, max_latency, avg_latency]

    if mode == 1:
        # Parse cache statistics
        ret = perf_res.stderr.read()
        reslines = ret.splitlines()
        L2_RQSTS_REFERENCES = int(reslines[3].split()[0])
        L2_RQSTS_MISS = int(reslines[4].split()[0])
        LONGEST_LAT_CACHE_REFERENCE = int(reslines[5].split()[0])
        LONGEST_LAT_CACHE_MISS = int(reslines[6].split()[0])
        INST_RETIRED_ANY = int(reslines[7].split()[0])
        L2_LINES_IN_ALL = int(reslines[8].split()[0])
        L2_LINES_OUT_NON_SILENT = int(reslines[9].split()[0])
        L2_LINES_OUT_SILENT = int(reslines[10].split()[0])
        L2_RQSTS_SWPF_HIT = int(reslines[11].split()[0])
        L2_RQSTS_SWPF_MISS = int(reslines[12].split()[0])
        SW_PREFETCH_ACCESS_T0 = int(reslines[13].split()[0])
        SW_PREFETCH_ACCESS_T1_T2 = int(reslines[14].split()[0])
        L1_dcache_loads = int(reslines[15].split()[0])
        L1_dcache_load_misses = int(reslines[16].split()[0])
        L1_icache_load_misses = int(reslines[17].split()[0])
        cycles = int(reslines[18].split()[0])
        instructions = int(reslines[19].split()[0])

        IPC = instructions/cycles

        LLC_miss_percent = f"{(LONGEST_LAT_CACHE_MISS / LONGEST_LAT_CACHE_REFERENCE) * 100:.4f}"
        L2_miss_percent = f"{(L2_RQSTS_MISS / L2_RQSTS_REFERENCES) * 100:.4f}"
        L1_dcache_miss_percent = f"{(L1_dcache_load_misses / L1_dcache_loads) * 100:.4f}"

        core0_int, core1_int = get_interrupt_counts()

        row = [" ", tx_pkts, rx_pkts, formatted_loss, curr_t, rx_dropped, rx_invalid, rx_queue_full, rx_fill_ring_empty, out_of_order, L1_dcache_miss_percent, L2_miss_percent, LLC_miss_percent, L1_dcache_loads, L1_dcache_load_misses, L1_icache_load_misses, L2_RQSTS_REFERENCES, L2_RQSTS_MISS, LONGEST_LAT_CACHE_REFERENCE, LONGEST_LAT_CACHE_MISS, INST_RETIRED_ANY, L2_LINES_IN_ALL, L2_LINES_OUT_NON_SILENT,
        L2_LINES_OUT_SILENT, L2_RQSTS_SWPF_HIT, L2_RQSTS_SWPF_MISS, SW_PREFETCH_ACCESS_T0, SW_PREFETCH_ACCESS_T1_T2,core0_int,core1_int,cycles,instructions,IPC,warm_count,cold_count]
        write_row_to_file(CACHE_FILENAME,row)

    if mode == 0:
        row = [" ",tx_pkts, rx_pkts, formatted_loss, curr_t, rx_dropped, rx_invalid, rx_queue_full,
               rx_fill_ring_empty, out_of_order]
        write_row_to_file(TP_FILENAME,row)
    
    # Clear pktgen statistics
    pktgen.sendline('cleanup()')
    pktgen.expect('cleanup-done')
    time.sleep(1)

    return loss, row


def run_till_zero(exp_cmd, mode, max_rate, pkt_size, duration, pktgen):
    curr_t = max_rate

    while True:
        loss, row = run_once(exp_cmd, mode, curr_t, pkt_size, 10000, pktgen)
        if loss < LOSS:
            curr_t = min(max_rate, curr_t + 4)
            break
        curr_t = curr_t - 5

    while True:
        loss, row = run_once(exp_cmd, mode, curr_t, pkt_size, 10000, pktgen)
        if loss < LOSS:
            curr_t = min(max_rate, curr_t + 1.5)
            break
        curr_t = curr_t - 2

    while True:
        loss, row = run_once(exp_cmd, mode, curr_t, pkt_size, duration, pktgen)
        if loss < LOSS:
            return row
        curr_t = curr_t - 0.5


def run_all(experiments, max_rate, pkt_size, duration, pktgen):
    for x in experiments:
        write_row_to_files(x)

        # # throughput
        # row = run_till_zero(x, 0, max_rate, pkt_size, duration, pktgen)
        # write_row_to_file(TP_FILENAME, row)

        # cache
        row = run_till_zero(x, 1, max_rate, pkt_size, duration, pktgen)
        write_row_to_file(CACHE_FILENAME, row)


        # # latency
        # row = run_till_zero(x, 2, max_rate, pkt_size, duration, pktgen)
        # write_row_to_file(LATENCY_FILENAME, row)


#######################   Setup   ##################################
# Write header

# header = ["MODE", 'tx_pkts', 'rx_pkts', 'loss %', 'curr_t', 'rx_dropped', 'rx_invalid', 'rx_queue_full',
#           'rx_fill_ring_empty', 'out_of_order', 'count_latency', 'min_latency', 'max_latency', 'avg_latency']
# write_row_to_file(LATENCY_FILENAME, header)

header = ["MODE", 'tx_pkts', 'rx_pkts', 'formatted_loss', 'curr_t',  'rx_dropped', 'rx_invalid', 'rx_queue_full',
          'rx_fill_ring_empty', 'out_of_order', 'L1_dcache_miss_percent', 'L2_miss_percent', 'LLC_miss_percent', 'L1_dcache_loads', 'L1_dcache_load_misses', 'L1_icache_load_misses','L2_RQSTS_REFERENCES', 'L2_RQSTS_MISS', 'LONGEST_LAT_CACHE_REFERENCE', 'LONGEST_LAT_CACHE_MISS', 'INST_RETIRED_ANY', 'L2_LINES_IN_ALL', 'L2_LINES_OUT_NON_SILENT',
    'L2_LINES_OUT_SILENT', 'L2_RQSTS_SWPF_HIT', 'L2_RQSTS_SWPF_MISS', 'SW_PREFETCH_ACCESS_T0', 'SW_PREFETCH_ACCESS_T1_T2','core0_int','core1_int','cycles','instructions','IPC','Warm_count','Cold_count']
write_row_to_file(CACHE_FILENAME, header)

# header = ["MODE", 'tx_pkts', 'rx_pkts', 'loss %', 'curr_t', 'rx_dropped', 'rx_invalid', 'rx_queue_full',
#            'rx_fill_ring_empty', 'out_of_order']
# write_row_to_file(TP_FILENAME, header)


# Setup pktgen
pktgen = pexpect.spawn('socat - TCP4:10.129.2.132:22022')
time.sleep(1)
pktgen.sendline(f'f,e=loadfile("{PKTGEN_SCRIPT}")')
time.sleep(1)
pktgen.sendline('f()')
time.sleep(1)
pktgen.sendline('setup()')
pktgen.expect('setup-done')
time.sleep(1)

# Set default configurations

INT_CORE = 1 # bit corresponds to core
set_interrupts_core()

# Setup busy polling
defer_napi_irqs()
set_gro_timeout()

prev = get_interrupt_counts()
MLC_ON =0
##############################################################

# app_type = [0,1,2,5]
# ideal_umem_size = [512,512,512,1024]
# ideal_ring_size =[2048,2048,4096,4096]

# app_type = [0,1,2,5]
app_type = [1]
# ideal_umem_size = [512,512,512,1024]
# ideal_ring_size =[2048,2048,4096,4096]

# umem_size=[16384,4096,2048,1024,512,256]
# ring_size=[8160,4096,2048,1024,512,256]


set_tx_ring_size(256)
time.sleep(1)


for i in range(len(app_type)):

    set_rx_ring_size(2048)
    time.sleep(1)
    myrow=["Ring size "+str(2048)]
    write_row_to_files(myrow)

    experiments = [
    ['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-s','512','-B','-A',str(app_type[i]),'-W'],

    ]
    run_all(experiments, 100, 512, 30000, pktgen)


    #set_rx_ring_size(1024)
    #time.sleep(1)
    #myrow=["Ring size "+str(1024)]
    #write_row_to_files(myrow)


    #experiments = [

    #['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-s','512','-B','-W','-A',str(app_type[i])],
    #]
    #run_all(experiments, 100, 512, 30000, pktgen)


    #set_rx_ring_size(256)
    #time.sleep(1)
    #myrow=["Ring size "+str(256)]
    #write_row_to_files(myrow)


    #experiments = [

    #['taskset', '-c', '0', 'sudo', APP_PATH, '-i', IFNAME, '-U','16384','-s','512','-B','-W','-A',str(app_type[i])],
    #]
    #run_all(experiments, 100, 512, 30000, pktgen)
