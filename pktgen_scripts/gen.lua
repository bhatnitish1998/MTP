package.path = package.path ..";?.lua;test/?.lua;app/?.lua;../?.lua;/usr/local?.lua;"
require "Pktgen"

-- parameters
file_path = "/home/magnus/nitish/MTP/pktgen_scripts/pkt_stat.txt"
rate = 40
packet_size = 256
duration = 3000


-- functions
function log_stats()

    local port = pktgen.portStats("0","port")
    local value = port[0].opackets

    local file = io.open(file_path, "w")
    file:write(tostring(value) .. "\n")
    file:close()

    pktgen.delay(1000)
end 

function wait_link()
    local linkState = pktgen.linkState(0)[0]
    local state = linkState:sub(2, 3)

    while(state ~= "UP") do
        pktgen.delay(1000)
        linkState = pktgen.linkState(0)[0]
        state = linkState:sub(2, 3)
    end
end


-- wait for link to be up
wait_link()

-- set configuration
pktgen.screen("off");
pktgen.delay(1000);

pktgen.set_mac("all", "src", "9c:69:b4:66:16:5d")
pktgen.set_mac("all", "dst", "9c:69:b4:66:16:54")
pktgen.set_ipaddr("all", "src", "192.168.201.1")
pktgen.set_ipaddr("all", "dst", "192.168.201.5")

pktgen.set_type("all", "ipv4");
pktgen.set_proto("all", "udp");

pktgen.delay(1000)

-- variable parameters
pktgen.set("all", "rate", rate);
pktgen.set("all", "size", packet_size);
pktgen.delay(1000)

-- start sending packets
pktgen.start("all")
pktgen.delay(duration)
pktgen.stop("all")
pktgen.delay(1000)


-- log results
log_stats()
pktgen.clear("all")


