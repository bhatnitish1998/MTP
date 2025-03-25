package.path = package.path ..";?.lua;test/?.lua;app/?.lua;../?.lua;/usr/local?.lua;"
require "Pktgen"

-- global parameters
file_path = "/home/magnus/nitish/MTP/pktgen_scripts/pkt_stat.txt";
latency_path = "/home/magnus/nitish/MTP/pktgen_scripts/latency.txt";


-- functions
function wait_link()
    local linkState = pktgen.linkState(0)[0]
    local state = linkState:sub(2, 3)

    while(state ~= "UP") do
        pktgen.delay(1000)
        linkState = pktgen.linkState(0)[0]
        state = linkState:sub(2, 3)
    end
end

function log_stats()

    local port = pktgen.portStats("0","port")
    local value = port[0].opackets

    local file = io.open(file_path, "w")
    file:write(tostring(value) .. "\n")
    file:close()

    pktgen.delay(1000)
end 

function enable_latency()
    pktgen.latency("all", "enable");
end

function disable_latency()
    pktgen.latency("all", "disable");
end


function log_latency()
    local port_stats = pktgen.pktStats("all");

    local min1 = port_stats[0].latency.min_us
    local max1 = port_stats[0].latency.max_us
    local avg1 = port_stats[0].latency.avg_us

    local file = io.open(latency_path, "w")
    file:write(tostring(min1) .. "\n")
    file:write(tostring(max1) .. "\n")
    file:write(tostring(avg1) .. "\n")
    file:close()
    pktgen.delay(1000)

end
----------------------------------------------------------

function setup()
-- wait for link to be up
    wait_link()

-- set configuration
    pktgen.delay(1000);

    pktgen.set_mac("all", "src", "9c:69:b4:66:16:5c")
    pktgen.set_mac("all", "dst", "9c:69:b4:66:16:54")
    pktgen.set_ipaddr("all", "src", "192.168.201.1")
    pktgen.set_ipaddr("all", "dst", "192.168.201.5")

    pktgen.set_type("all", "ipv4");
    pktgen.set_proto("all", "udp");

    
    pktgen.delay(1000)
    printf("setup-done\n");
end


function configure(rate,packet_size)
    pktgen.set("all", "rate", rate);
    pktgen.set("all", "size", packet_size);
    pktgen.delay(1000)
    printf("config-done\n");
end


function multi_configure(rate,packet_size)


    pktgen.delay(1000);
    pktgen.range.dst_ip("all", "start", "192.168.201.5");
    pktgen.range.dst_ip("all", "inc", "0.0.0.0");
    pktgen.range.dst_ip("all", "min", "192.168.201.5");
    pktgen.range.dst_ip("all", "max", "192.168.201.5");

    pktgen.delay(1000);
    pktgen.range.src_ip("all", "start", "192.168.201.1");
    pktgen.range.src_ip("all", "inc", "0.0.0.0");
    pktgen.range.src_ip("all", "min", "192.168.201.1");
    pktgen.range.src_ip("all", "max", "192.168.201.1");


    pktgen.range.dst_mac("all", "start", "9c:69:b4:66:16:54");
    pktgen.range.src_mac("all", "start", "9c:69:b4:66:16:54");


    pktgen.set("all", "rate", rate);
    pktgen.set("all", "size", packet_size);
    pktgen.delay(1000);
    pktgen.range.dst_port("all", "start", 1234);
    pktgen.range.dst_port("all", "inc", 4);
    pktgen.range.dst_port("all", "min", 1234);
    pktgen.range.dst_port("all", "max", 2345);

    pktgen.delay(1000);
    pktgen.range.src_port("all", "start", 5678);
    pktgen.range.src_port("all", "inc", 5);
    pktgen.range.src_port("all", "min", 1234);
    pktgen.range.src_port("all", "max", 9999);
    
    pktgen.set_range("all", "on");
    pktgen.delay(1000);
    printf("config-done\n");
end

function run(duration,mode)
    if(mode =="1")
    then 
        enable_latency();
    end

    pktgen.delay(1000)
    pktgen.start("all")
    pktgen.delay(duration)
    pktgen.stop("all")
    pktgen.delay(1000)
    log_stats()
    if(mode =="1")
    then
        log_latency();
        pktgen.delay(1000)
        disable_latency();
    end
    pktgen.delay(1000)
    printf("run-done\n");
end

function run_burst(duration,interval_time,rate,burst_count)
    duration = tonumber(duration)
    interval_time = tonumber(interval_time)
    burst_count = tonumber(burst_count)

    local intervals = duration/interval_time
    local iteration = 0

    pktgen.set("all", "rate", rate)
    pktgen.set("all","count",burst_count)
    while (iteration < intervals) do
        pktgen.start("all")
        pktgen.delay(interval_time)
        pktgen.stop("all")
        pktgen.delay(interval_time)
        iteration = iteration + 2
    end
    pktgen.stop("all")
    pktgen.set("all","count",0)
    pktgen.delay(1000)
    log_stats()
    pktgen.delay(1000)
    printf("run-done\n");
end

-- Pattern is like  normal duration  burst duration normal burst .....
-- all duration in milliseconds
-- duration should be multiple of (normal + burst)
function run_mixed(duration,normal_duration,burst_duration,rate,burst_count)
    duration = tonumber(duration)
    normal_duration = tonumber(normal_duration)
    burst_duration = tonumber(burst_duration)
    burst_count = tonumber(burst_count)
    interval_time = 1
    local intervals = burst_duration/interval_time


    current_duration =0
    while(current_duration < duration) do
       
        pktgen.set("all", "rate", rate)
        pktgen.start("all")
        pktgen.delay(normal_duration)
        pktgen.stop("all")
        current_duration = current_duration + normal_duration


        local iteration = 0
        pktgen.set("all", "rate", 100)
        pktgen.set("all","count",burst_count)
        while (iteration < intervals) do
            pktgen.start("all")
            pktgen.delay(interval_time)
            pktgen.stop("all")
            pktgen.delay(interval_time)
            iteration = iteration + 2
        end
        pktgen.set("all","count",0)

        current_duration = current_duration + burst_duration
    end 

    log_stats()
    pktgen.delay(1000)
    printf("run-done\n");
end


function cleanup()
    pktgen.clear("all")
    pktgen.delay(1000)
    printf("cleanup-done\n");
end

