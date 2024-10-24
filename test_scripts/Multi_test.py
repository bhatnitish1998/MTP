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
APP_PATH = f'/home/magnus/nitish/MTP/bpf/multi_XDP/{APP_NAME}'

TP_FILENAME = 'tp_results.csv'

EXP_TIME = 30

LOSS = 0.001

INT_CORES = 4

######### Interrupt params

def defer_napi_irqs():
    command = 'echo 2 > /sys/class/net/ens19f0np0/napi_defer_hard_irqs'
    subprocess.run(['sudo', 'bash', '-c', command], check=True)

# interval in 100 micro
def set_gro_timeout():
    command = f'echo 200000 > /sys/class/net/ens19f0np0/gro_flush_timeout'
    subprocess.run(['sudo', 'bash', '-c', command], check=True)


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


def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:{PKTGEN_STAT}', '.']
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    with open("pkt_stat.txt", "r") as f:
        ret = f.read().splitlines()
    return int(ret[0])


def kill_processes():
    cmd = ['pidof', APP_NAME]
    ret = subprocess.run(cmd, capture_output=True, text=True)
    pids = ret.stdout.split()

    for pid in pids:
        cmd = ['sudo', 'kill', '-SIGINT', pid]
        subprocess.run(cmd)
    time.sleep(3)

def get_rcvd_pkts():
    value =0
    for i in range (INT_CORES):
        with open(f"./logs/stats{i}.csv", mode='r') as file:
            reader = csv.reader(file)
            rows = list(reader)
        value = value + int(rows[0][1])

    return value

def write_row_to_files(row):
    with open(TP_FILENAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)


# mode 0 = throughput   

def run_once(exp_cmds, curr_t, pkt_size, duration, pktgen):

    rx_queue_full = -1
    row = []

    # setup
    flushllc = subprocess.run(['/home/magnus/nitish/MTP/cache/flush'], capture_output=True, text=True)

    # start xdp
    for curr_cmd in exp_cmds:
        app = subprocess.Popen(curr_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(1)
    
    # configure pktgen
    pktgen.sendline(f'configure("{curr_t}","{pkt_size}")')
    pktgen.expect('config-done')

    pktgen.sendline(f'run("{duration}","{0}")')

    time.sleep(1)

    # wait for pktgen
    pktgen.expect('run-done',timeout = 120)
    time.sleep(1)
    # terminate processes
    kill_processes()
    time.sleep(1)
    
    # get loss
    tx_pkts = get_pktgen_stats()
    rx_pkts = get_rcvd_pkts()
    if tx_pkts != 0:
        loss = (tx_pkts - rx_pkts) / tx_pkts
    else:
        loss = 1


    print(f'Target {curr_t} Gbps, loss {loss * 100:.2f}%\n')

    formatted_loss = f"{loss * 100:.3f}"


    row = [" ",tx_pkts, rx_pkts, formatted_loss, curr_t]
    write_row_to_files(row)
    
    # Clear pktgen statistics
    pktgen.sendline('cleanup()')
    pktgen.expect('cleanup-done')
    time.sleep(1)

    return loss, row


def run_till_zero(exp_cmds, max_rate, pkt_size, duration, pktgen):
    curr_t = max_rate

    while True:
        loss, row = run_once(exp_cmds, curr_t, pkt_size, 10000, pktgen)
        if loss < LOSS:
            curr_t = min(max_rate, curr_t + 4)
            break
        curr_t = curr_t - 5

    while True:
        loss, row = run_once(exp_cmds,curr_t, pkt_size, 10000, pktgen)
        if loss < LOSS:
            curr_t = min(max_rate, curr_t + 1.5)
            break
        curr_t = curr_t - 2

    while True:
        loss, row = run_once(exp_cmds,curr_t, pkt_size, duration, pktgen)
        if loss < LOSS:
            return row
        curr_t = curr_t - 0.5


def run_all(exp_cmds, max_rate, pkt_size, duration, pktgen):

    # throughput
    row = run_till_zero(exp_cmds, max_rate, pkt_size, duration, pktgen)
    write_row_to_files(row)


def setup_and_generate_commands(cores, umem_size,packet_size,app_type):
    command = f"sudo ethtool -L ens19f0np0 combined {cores}"
    subprocess.run(['sudo', 'bash', '-c', command], check=True)

    cmds = []
    for i in range(cores):
        cmds.append(['taskset', '-c', str(i), 'sudo', APP_PATH, '-i', IFNAME,'-q',str(i), '-U',str(umem_size),'-s',str(packet_size),'-B','-W','-A',str(app_type)])
    
    return cmds




#######################   Setup   ##################################


header = ["MODE", 'tx_pkts', 'rx_pkts', 'loss %', 'curr_t']
write_row_to_files(header)


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

# Setup busy polling
defer_napi_irqs()
set_gro_timeout()

##############################################################

APP_TYPE = 1

set_rx_ring_size(256)
time.sleep(1)
myrow=["Ring size "+str(256)]
write_row_to_files(myrow)


myrow=["PKT 64 "]
write_row_to_files(myrow)

INT_CORES = 4

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,64,APP_TYPE)
run_all(cmds, 100, 64, 30000, pktgen)


INT_CORES = 2

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,64,APP_TYPE)
run_all(cmds, 60, 64, 30000, pktgen)


INT_CORES = 1

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,64,APP_TYPE)
run_all(cmds, 30, 64, 30000, pktgen)



myrow=["PKT 256 "]
write_row_to_files(myrow)

INT_CORES = 4

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,256,APP_TYPE)
run_all(cmds, 100, 256, 30000, pktgen)



INT_CORES = 2

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,256,APP_TYPE)
run_all(cmds, 80, 256, 30000, pktgen)


INT_CORES = 1

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,256,APP_TYPE)
run_all(cmds, 70, 256, 30000, pktgen)


myrow=["PKT 512 "]
write_row_to_files(myrow)

INT_CORES = 4

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,512,APP_TYPE)
run_all(cmds, 100, 512, 30000, pktgen)



INT_CORES = 2

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,512,APP_TYPE)
run_all(cmds, 100, 512, 30000, pktgen)


INT_CORES = 1

myrow=["Cores "+str(INT_CORES)]
write_row_to_files(myrow)

cmds = setup_and_generate_commands(INT_CORES,16384,512,APP_TYPE)
run_all(cmds, 100, 512, 30000, pktgen)
