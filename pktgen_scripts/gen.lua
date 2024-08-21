package.path = package.path ..";?.lua;test/?.lua;app/?.lua;../?.lua;/usr/local?.lua;"
require "Pktgen"

-- global parameters
file_path = "/home/magnus/nitish/MTP/pktgen_scripts/pkt_stat.txt"

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

-- functions
function log_stats()

    local port = pktgen.portStats("0","port")
    local value = port[0].opackets

    local file = io.open(file_path, "w")
    file:write(tostring(value) .. "\n")
    file:close()

    pktgen.delay(1000)
end 

----------------------------------------------------------

function setup()
-- wait for link to be up
    wait_link()

-- set configuration
    pktgen.delay(1000);

    pktgen.set_mac("all", "src", "9c:69:b4:66:16:5d")
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


function run(duration)
    pktgen.delay(1000)
    pktgen.start("all")
    pktgen.delay(duration)
    pktgen.stop("all")
    pktgen.delay(1000)
    log_stats()
    pktgen.delay(1000)
    printf("run-done\n");
end


function cleanup()
    pktgen.clear("all")
    pktgen.delay(1000)
    printf("cleanup-done\n");
end

