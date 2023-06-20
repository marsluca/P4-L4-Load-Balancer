/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORT_WIDTH 9

#define CLIENT_PORT_IDX 1

#define BACKEND1_IDX 2
#define BACKEND2_IDX 3
#define BACKEND3_IDX 4
#define BACKEND4_IDX 5

#define BACKEND_REGISTER_ENTRIES 65535
#define BACKEND_SERVERS 4

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/* Ethernet header definition*/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* IPv4 header definition */
header ipv4_t {
    bit<4>  ihl;
    bit<4>  version;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* TCP header definition */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* Metadata structure is used to pass information
 * across the actions, or the control block.
 * It is also used to pass information from the 
 * parser to the control blocks.
 */
struct metadata {
    bit<16> l4_payload_length;
    /* Used to understand if the packet belongs to a configured VIP */
    bit<1> pkt_is_virtual_ip;
    /* Used to keep track of the current backend assigned to a connection */
    bit<9> assigned_backend;
    /* TODO: Add here other metadata */
    bit<32> assigned_backend_hash;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    /* Parsing the Ethernet header */
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    /* Parsing the IPv4 header */
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        /* This information is used to recalculate the checksum 
         * in the MyComputeChecksum control block.
         * Since we modify the TCP header, we need to recompute the checksum.
         * We do it for you, so don't worry about it.
         */
        meta.l4_payload_length = hdr.ipv4.totalLen - (((bit<16>)hdr.ipv4.ihl) << 2);

        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    /* Parsing the TCP header */
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Register to keep information about the backend assigned to a connection
     * value 2 -> Backend 2
     * value 3 -> Backend 3
     * value 4 -> Backend 4
     * value 5 -> Backend 5
     * value 0 -> No backend assigned
     */
    register<bit<9>>(BACKEND_REGISTER_ENTRIES) r_assigned_backend;

    /* Register to keep information about the number of connections assigned to a backend
     * Index 0 -> Backend 2
     * Index 1 -> Backend 3
     * Index 2 -> Backend 4
     * Index 3 -> Backend 5
     */
    register<bit<32>>(BACKEND_SERVERS) r_connections_count;

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
        return;
    }

    // Forward action 
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* This action is executed after a lookup on the vip_to_backend table
     * Redirecting the packet from CLIENT to BACKEND
     * and update the relative fields. (IP, MAC and TCP port).
     */
    action update_backend_info(bit<32> ip, bit<16> port, bit<48> dstMac) {
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.dstAddr = ip;
        hdr.tcp.dstPort = port;
        //decrease ttl by 1
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;    
    }

    /* Define here all the other actions that you might need */

    /* Logic to assign a new backend to the connection.
     * It assigns the backend with the minimum number of connections.
     * If there are multiple backends with the same number of connections,
     * it assigns the backend with the lowest index.
     */
    action min_r_connections_count(out bit<32> min, out bit<32> index) {
        bit<32> tmp;
        index = 0;

        r_connections_count.read(min, index);
        log_msg(">>> Checking backend {}, {} connections.", {(bit<9>)BACKEND1_IDX, min});

        r_connections_count.read(tmp, 1);
        log_msg(">>> Checking backend {}, {} connections.", {(bit<9>)BACKEND2_IDX, tmp});
        if (tmp < min) {
            min = tmp;
            index = 1;
        }
        log_msg(">>> Checking backend {}, {} connections.", {(bit<9>)BACKEND3_IDX, tmp});
        r_connections_count.read(tmp, 2);
        if (tmp < min) {
            min = tmp;
            index = 2;
        }
        log_msg(">>> Checking backend {}, {} connections.", {(bit<9>)BACKEND4_IDX, tmp});
        r_connections_count.read(tmp, 3);
        if (tmp < min) {
            min = tmp;
            index = 3;
        }        
    }

    /* This action is executed to check if the current packet is 
     * destined to a virtual IP configured on the load balancer.
     * This action is complete, you don't need to change it.
     */
    action is_virtual_ip(bit<1> val) {
        meta.pkt_is_virtual_ip = val;
    }

    /* This action is executed for packets coming from the backend servers.
     * You need to update the packet fields before redirecting the packet
     * to the client.
     * This action is executed after a lookup on the backend_to_vip table.
     */
    action backend_to_vip_conversion(bit<32> srcIP, bit<16> port, bit<48> srcMac) {
        hdr.ipv4.srcAddr = srcIP;
        hdr.tcp.srcPort = port; 
        hdr.ethernet.srcAddr = srcMac;
        //decrease ttl by 1
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* Table used to understand if the current packet is destined 
     * to a configured virtual IP 
     */
    table virtual_ip {
        key = {
            hdr.ipv4.dstAddr : exact;
            hdr.tcp.dstPort : exact;
        }
        actions = {
            is_virtual_ip;
            drop;
        }
        default_action = drop();
    }

    /* Table used to map a backend with the information about the VIP */
    table backend_to_vip {
        key = {
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            backend_to_vip_conversion;
            drop;
        }
        default_action = drop();
    }

    /* Table used map a backend index with its information */
    table vip_to_backend {
        key = {
            meta.assigned_backend : exact;
        }
        actions = {
            update_backend_info;
            drop;
        }
        default_action = drop();
    }

    apply {  
        /* Check if the ingress port is the one connected to the client. 
         *
         * Verify whether the packet is destined for the Virtual IP 
         * If not, drop the packet.
         * If yes, continue with the ingress logic
         */
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if (standard_metadata.ingress_port == CLIENT_PORT_IDX) {
                switch (virtual_ip.apply().action_run) {
                    is_virtual_ip: {
                        bit<32> connections_count;
                        bit<32> r_connections_index;

                        /* Check if the current connection is already assigned to a specific 
                         * backend server. 
                         * If yes, forward the packet to the assigned backend (but first check the FIN or RST flag).
                         * If not, assign a new backend to the connection (only is the packet has the SYN flag set)
                         * otherwise, drop the packet.
                         */

                        hash(meta.assigned_backend_hash, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                                hdr.ipv4.dstAddr,
                                                                hdr.tcp.srcPort,
                                                                hdr.tcp.dstPort,
                                                                hdr.ipv4.protocol},
                                                                (bit<32>)BACKEND_REGISTER_ENTRIES);

                        // Read the assigned backend from the register
                        r_assigned_backend.read(meta.assigned_backend, meta.assigned_backend_hash);

                        // If connection is assigned to a backend
                        if (meta.assigned_backend != 0) {   
                            /* If the packet is already assigned, and if the FIN or RST flags are enabled 
                             * it removes the assignment and decrement the number of connections
                             * for the backend. Finally, forward the packet to the backend.
                             */
                            
                            // Subtract 2 because beckend servers starts from 2 and register indexes from 0
                            r_connections_index = (bit<32>)meta.assigned_backend - 2;
                    
                            r_connections_count.read(connections_count, r_connections_index);
                            log_msg("[MAPPED CONNECTION]>>> There are {} connections assigned to backend {}", {connections_count, meta.assigned_backend});
                            // If FIN or RST flag is set, remove the backend assignment
                            if (hdr.tcp.fin == 1 || hdr.tcp.rst == 1) {
                                r_assigned_backend.write(meta.assigned_backend_hash, 0);
                                r_connections_count.write(r_connections_index, connections_count-1);
                                log_msg(">>> FIN or RST flag set, backed assignment removed!");
                            }

                        // If connection is NOT assigned to a backend
                        } else {
                            log_msg("[NEW CONNECTION]>>> Checking SYN flag...");
                            // If SYN flag is 1 and ACK flag is 0 assign a backend with least connections
                            if (hdr.tcp.syn == 1) {
                                log_msg(">>> SYN flag setted to 1 checking the ACK flag...");
                                if (hdr.tcp.ack == 1) {
                                    log_msg(">>> ACK flag setted to 1, PACKET DROPPED!");
                                    drop();
                                    return;
                                } else {
                                    log_msg(">>> ACK flag setted to 0, assigning a backend...");
                                    // Find the index of the backend server with the least connections inside r_assigned_backend data structure
                                    min_r_connections_count(connections_count, r_connections_index);
                                    // Backed server ID = register index + 2
                                    meta.assigned_backend = (bit<9>)r_connections_index + (bit<9>)2;
                                    // Increment the number of connections for the assigned backend
                                    connections_count = connections_count + 1;
                                    r_connections_count.write(r_connections_index, connections_count);
                                    r_assigned_backend.write(meta.assigned_backend_hash, meta.assigned_backend);
                                    log_msg(">>> Backend {} assigned, now {} connections.", {meta.assigned_backend, connections_count});
                                }
                            } else {
                                log_msg(">>> SYN flag setted to 0, PACKET DROPPED!");
                                drop();
                                return;
                            }
                        }
                        log_msg(">>> Forwarding packet to backend {}...", {meta.assigned_backend});
                        switch (vip_to_backend.apply().action_run) {
                            update_backend_info: {
                                forward(meta.assigned_backend);
                            }
                            drop: {
                                log_msg("[DROP]>>> No matching backend found");
                                return;
                            }
                        }

                    }
                    drop: {
                        log_msg("[DROP]>>> VIP received a packet not destined to a virtual IP");
                        return;
                    }
                }
            }
        } else if (standard_metadata.ingress_port == BACKEND1_IDX || 
                standard_metadata.ingress_port == BACKEND2_IDX || 
                standard_metadata.ingress_port == BACKEND3_IDX ||
                standard_metadata.ingress_port == BACKEND4_IDX) {
            // Forward to the client
            switch (backend_to_vip.apply().action_run) {
                    backend_to_vip_conversion: {
                        forward(CLIENT_PORT_IDX);
                    }
                    drop: {
                        log_msg("[DROP]>>> Backend received a packet from a configured backed port but from an unknown IP.");
                        return;
                    }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        // Note: the following does not support TCP options.
        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.ipv4.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4_payload_length,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.cwr,
                hdr.tcp.ece,
                hdr.tcp.urg,
                hdr.tcp.ack,
                hdr.tcp.psh,
                hdr.tcp.rst,
                hdr.tcp.syn,
                hdr.tcp.fin,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        log_msg(">>> Ethernet srcAddr {}", {hdr.ethernet.srcAddr});
        log_msg(">>> Ethernet dstAddr {}", {hdr.ethernet.dstAddr});
        log_msg(">>> Ethernet etherType {}", {hdr.ethernet.etherType});
        log_msg(">>> IPv4 version {}", {hdr.ipv4.version});
        log_msg(">>> IPv4 ihl {}", {hdr.ipv4.ihl});
        log_msg(">>> IPv4 diffserv {}", {hdr.ipv4.diffserv});
        log_msg(">>> IPv4 totalLen {}", {hdr.ipv4.totalLen});
        log_msg(">>> IPv4 identification {}", {hdr.ipv4.identification});
        log_msg(">>> IPv4 flags {}", {hdr.ipv4.flags});
        log_msg(">>> IPv4 fragOffset {}", {hdr.ipv4.fragOffset});
        log_msg(">>> IPv4 ttl {}", {hdr.ipv4.ttl});
        log_msg(">>> IPv4 protocol {}", {hdr.ipv4.protocol});
        log_msg(">>> IPv4 hdrChecksum {}", {hdr.ipv4.hdrChecksum});
        log_msg(">>> IPv4 srcAddr {}", {hdr.ipv4.srcAddr});
        log_msg(">>> IPv4 dstAddr {}", {hdr.ipv4.dstAddr});
        log_msg(">>> TCP srcPort {}", {hdr.tcp.srcPort});
        log_msg(">>> TCP dstPort {}", {hdr.tcp.dstPort});
        log_msg(">>> TCP seqNo {}", {hdr.tcp.seqNo});
        log_msg(">>> TCP ackNo {}", {hdr.tcp.ackNo});
        log_msg(">>> TCP dataOffset {}", {hdr.tcp.dataOffset});
        log_msg(">>> TCP res {}", {hdr.tcp.res});
        log_msg(">>> TCP cwr {}", {hdr.tcp.cwr});
        log_msg(">>> TCP ece {}", {hdr.tcp.ece});
        log_msg(">>> TCP urg {}", {hdr.tcp.urg});
        log_msg(">>> TCP ack {}", {hdr.tcp.ack});
        log_msg(">>> TCP psh {}", {hdr.tcp.psh});
        log_msg(">>> TCP rst {}", {hdr.tcp.rst});
        log_msg(">>> TCP syn {}", {hdr.tcp.syn});
        log_msg(">>> TCP fin {}", {hdr.tcp.fin});
        log_msg(">>> TCP window {}", {hdr.tcp.window});
        log_msg(">>> TCP checksum {}", {hdr.tcp.checksum});
        log_msg(">>> TCP urgentPtr {}", {hdr.tcp.urgentPtr});
        //log_msg(">>> IPv4 checksum decimal {}", {hdr.ipv4.hdrChecksum});
        //log_msg(">>> TCP checksum decimal {}", {hdr.tcp.checksum});

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;