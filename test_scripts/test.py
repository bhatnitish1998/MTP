import os
import subprocess
from subprocess import PIPE
import time
import csv

curdir = os.path.dirname(__file__)

TESTER             = 'preeti@10.129.2.253'
IFNAME             = 'ens261f1'

MOONGEN_PATH       = '~/nitish/MoonGen/build/MoonGen'
PKTGEN_SCRIPT_PATH = '~/nitish/MoonGen/examples/preeti/check.lua'

APP_NAME           = 'xdpsock'
APP_PATH           = f'/home/preeti/nitish/MTP/bpf/AF_XDP/{APP_NAME}'

LATENCY_FILENAME   = 'latency_results.csv'
CACHE_FILENAME     = 'cache_results.csv'

PKT_SIZE           = 64
MAX_TARGET         = 4500
TARGET_STEP        = 100

EXP_TIME          = 30

PERF_COUNTERS      = ['LLC-loads', 'LLC-load-misses', 'LLC-stores', 'LLC-store-misses', 
			'L1-dcache-loads', 'L1-dcache-load-misses', 'L1-dcache-stores', 'L1-icache-misses',
          'l2_rqsts.references', 'l2_rqsts.miss', 'l2_rqsts.all_pf', 'l2_rqsts.l2_pf_hit', 'l2_rqsts.l2_pf_miss', 'instructions']


experiments =[

# Sequential and Random
['taskset', '-c', '0', 'sudo', APP_PATH,'-i', IFNAME,'-U','16384'],
['taskset', '-c', '0', 'sudo', APP_PATH,'-i', IFNAME ,'-R','-U','16384'],

# With busy loop
['taskset', '-c', '0', 'sudo', APP_PATH,'-i', IFNAME,'-U','16384','-B'],
['taskset', '-c', '0', 'sudo', APP_PATH,'-i', IFNAME ,'-R','-U','16384','-B'],

]


def change_ddio(value):
    cmd = ['sudo', '/home/preeti/nitish/MTP/ddio/change-ddio',str(value)]
    ret = subprocess.run(cmd)

def change_prefetch(value):
    if(value):
        cmd = ['sudo','wrmsr','0x1a4','-a','0']
        ret = subprocess.run(cmd)
    else:
        cmd = ['sudo','wrmsr','0x1a4','-a','15']
        ret = subprocess.run(cmd)

def set_interrupts_core():
    command = "echo 1 > /proc/irq/105/smp_affinity"
    subprocess.run(['sudo', 'bash', '-c', command], check=True)

def kill_process():
    cmd = ['pidof', APP_NAME]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    print(f'pid: {ret}')
    cmd = ['sudo', 'kill', '-SIGINT', str(int(ret.stdout))]
    ret = subprocess.run(cmd)
    time.sleep(5)

def get_rcvd_pkts():
    with open("./logs/stats.csv", mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)
    value = rows[0][1]
    return int(value) 

def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:./tmp.csv' , '.']
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    f = open("tmp.csv", "r")
    ret = f.read().splitlines()[1].split(';')
    f.close()
    return ret[0], int(ret[1])

def get_latency_data():
    with open('./logs/latency_data.txt', 'r') as file:
        data = file.read()
    values = data.split(',')
    values = [float(value) if '.' in value else int(value) for value in values]
    return values

def write_string_to_file(text):
    with open(LATENCY_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([text])

    with open(CACHE_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([text])


# mode 0 = cache     mode 1 = latency
def run_exp(exp_cmd,mode):
    if mode == 1:
        exp_cmd.append('-L')

    print(exp_cmd)

    curr_t = MAX_TARGET
    rx_queue_full = 9999999
    run = 0

    while int(rx_queue_full) !=0 :
        print(f'Run {run}:')

        flushllc = subprocess.run(['/home/preeti/nitish/cache/flush'], capture_output=True, text=True)
        set_interrupts_core()
        app = subprocess.Popen(exp_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cmd = ['ssh', TESTER, 'sudo', 'taskset', '-c', '0-11', MOONGEN_PATH, PKTGEN_SCRIPT_PATH, '0', '0', '-c', '1', '-o', 'tmp.csv', '-s', str(PKT_SIZE), '-r', str(curr_t), '-t', str(EXP_TIME)]
        pktgen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(7)
            
        if mode == 0:
            cmd = ['pidof', APP_NAME]
            pid = subprocess.run(cmd, capture_output=True, text=True)
            perf = ['sudo', 'perf', 'stat', '--no-big-num', '-e',','.join(PERF_COUNTERS), '-p', str(int(pid.stdout))]
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

        print(f'Target {curr_t} Mbps, loss {loss*100:.2f}%, RX queue full {rx_queue_full}, out of order {out_of_order}\n')  
        
        if int(rx_queue_full)==0:
            formatted_loss = f"{loss*100:.3f}"

            if mode == 1:
            # Parse Latency statistics
                latency_values = get_latency_data()
                count_latency = latency_values[0]
                min_latency = latency_values[1]
                max_latency = latency_values[2]
                avg_latency = latency_values[3]
                tail99_latency = latency_values[4]
                tail999_latency = latency_values[5]

                with open(LATENCY_FILENAME, 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([" ",tx_pkts,rx_pkts,formatted_loss,curr_t,rate,rx_dropped,rx_invalid,rx_queue_full,rx_fill_ring_empty,out_of_order,count_latency,min_latency,max_latency,avg_latency,tail99_latency,tail999_latency])

            if mode == 0:
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


                LLC_load_miss_percent = (LLC_load_misses/ LLC_loads) * 100
                LLC_store_miss_percent = (LLC_store_misses/ LLC_stores)* 100
                L1_dcache_load_miss_percent = (L1_dcache_load_misses/L1_dcache_loads) *100
                L2_miss_percent = ( l2_rqsts_miss / l2_rqsts_references ) * 100
                L2_pf_hit_percent = (l2_rqsts_l2_pf_hit / l2_rqsts_all_pf ) * 100
                L2_pf_miss_percent = (l2_rqsts_l2_pf_miss / l2_rqsts_all_pf) * 100

 
                with open(CACHE_FILENAME, 'a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([" ",tx_pkts,rx_pkts,formatted_loss,curr_t,rate,rx_dropped,rx_invalid,rx_queue_full,rx_fill_ring_empty,out_of_order,LLC_loads,LLC_load_misses,LLC_stores,LLC_store_misses,L1_dcache_loads,L1_dcache_load_misses,L1_dcache_stores,L1_icache_misses,l2_rqsts_references,l2_rqsts_miss,l2_rqsts_all_pf,l2_rqsts_l2_pf_hit,l2_rqsts_l2_pf_miss,instructions,LLC_load_miss_percent,LLC_store_miss_percent,L1_dcache_load_miss_percent,L2_miss_percent,L2_pf_hit_percent,L2_pf_miss_percent])

        curr_t = curr_t - TARGET_STEP

        run += 1
        time.sleep(5)


def run_all():
    for x in experiments:
        with open(LATENCY_FILENAME, 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([" ".join(x)])
        run_exp(x,1)

        with open(CACHE_FILENAME,'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([" ".join(x)])
        run_exp(x,0)

##########################################################

# Write header
with open(LATENCY_FILENAME, 'a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["MODE",'tx_pkts','rx_pkts','loss %','curr_t','rate','rx_dropped','rx_invalid','rx_queue_full','rx_fill_ring_empty','out_of_order','count_latency','min_latency','max_latency','avg_latency','tail99_latency','tail999_latency'])

with open(CACHE_FILENAME, 'a', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["MODE",'tx_pkts','rx_pkts','formatted_loss','curr_t','rate','rx_dropped','rx_invalid','rx_queue_full','rx_fill_ring_empty','out_of_order','LLC_loads','LLC_load_misses','LLC_stores','LLC_store_misses','L1_dcache_loads','L1_dcache_load_misses','L1_dcache_stores','L1_icache_misses','l2_rqsts_references','l2_rqsts_miss','l2_rqsts_all_pf','l2_rqsts_l2_pf_hit','l2_rqsts_l2_pf_miss','instructions','LLC_load_miss_percent','LLC_store_miss_percent','L1_dcache_load_miss_percent','L2_miss_percent','L2_pf_hit_percent','L2_pf_miss_percent'])
    
# PREFETCH ENABLED
change_prefetch(1)
write_string_to_file("PF ON")

# DDIO OFF
change_ddio(0)
write_string_to_file("DDIO OFF")
run_all()

# DDIO ON
change_ddio(1)
write_string_to_file("DDIO ON")
run_all()

#####################

# PREFETCH DISABLED
change_prefetch(0)
write_string_to_file("PF OFF")

# DDIO OFF
change_ddio(0)
write_string_to_file("DDIO OFF")
run_all()

# DDIO ON
change_ddio(1)
write_string_to_file("DDIO ON")
run_all()
