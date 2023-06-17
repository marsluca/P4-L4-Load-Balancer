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
    bit<8>  flags;
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
}


struct headers {
    ethernet_t eth;
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
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
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

    // Register to keep information about the backend assigned to a connection
    register<bit<9>>(BACKEND_REGISTER_ENTRIES) r_assigned_backend;

    // Register to keep information about the number of connections assigned to a backend
    register<bit<32>>(BACKEND_SERVERS) r_connections_count;

    /* Drop action */
    action drop() {
        mark_to_drop(standard_metadata);
        return;
    }

    /* Forward action */
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    /* This action is executed after a lookup on the vip_to_backend table */
    action update_backend_info(bit<32> ip, bit<16> port, bit<48> dstMac) {
        /* TODO 16: Update the packet fields before redirecting the 
         * packet to the backend.
         */
    }

    /* Define here all the other actions that you might need */

    //Check in r_connections_count the entry with the lowest number of connections between indexes 0 and 3 without using for loop or while loop
    action min_r_connections_count(out bit<32> min, out bit<9> index) {
        bit<32> min;
        bit<32> tmp;
        bit<9> index = 0;
        r_connections_count.read(min, index);

        r_connections_count.read(tmp, 1);
        log_msg("\t\t> Checking backend {}, {} connections.", {1+(bit<9>)2, tmp});
        if (tmp < min) {
            min = tmp;
            index = 1;
        }
        log_msg("\t\t> Checking backend {}, {} connections.", {2+(bit<9>)2, tmp});
        r_connections_count.read(tmp, 2);
        if (tmp < min) {
            min = tmp;
            index = 2;
        }
        log_msg("\t\t> Checking backend {}, {} connections.", {3+(bit<9>)2, tmp});
        r_connections_count.read(tmp, 3);
        if (tmp < min) {
            min = tmp;
            index = 3;
        }        
    }

    /* Check if the current connection is already assigned to a specific 
    * backend server. 
    * If yes, forward the packet to the assigned backend (but first check the FIN or RST flag).
    * If not, assign a new backend to the connection (only is the packet has the SYN flag set)
    * otherwise, drop the packet.
    */
    action check_backend_assignment() {
        bit<32> assigned_backend_index;
        hash(assigned_backend_index, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                    hdr.ipv4.dstAddr,
                                                    srcPort,
                                                    dstPort,
                                                    hdr.ipv4.protocol},
                                                    (bit<32>)BACKEND_REGISTER_ENTRIES);

        bit<32> connections_count;
        r_assigned_backend.read(meta.assigned_backend, assigned_backend_index);

        // If connection is assigned to a backend
        if (meta.assigned_backend != 0) {   
            r_connections_count.read(connections_count, meta.assigned_backend);
            log_msg("[MAPPED CONNECTION] There are {} connections assigned to backend {}", {connections_count, meta.assigned_backend});

            if (hdr.tcp.flags == TCP_FLAG_FIN || hdr.tcp.flags == TCP_FLAG_RST) {
                r_assigned_backend.write(assigned_backend_index, 0);
                // Subtract 2 because beckend servers starts from 2 and register indexes from 0
                r_connections_count.write(meta.assigned_backend - (bit<9>)2, connections_count-1);
                log_msg("\t\t> FIN or RST flag set, backed assignment removed!");
            }
            forward(meta.assigned_backend);
            log_msg("\t\t> Forwarding packet to backend {}...", {meta.assigned_backend});
        // If connection is NOT assigned to a backend
        } else {
            log_msg("[NEW CONNECTION] Checking SYN flag...");
            // If SYN flag is 1 and ACK flag is 0 assign a backend with least connections
            if (hdr.tcp.flags == TCP_FLAG_SYN) {
                log_msg("\t\t> SYN flag setted to 1 checking the ACK flag...");
                if (hdr.tcp.flags != TCP_FLAG_ACK) {
                    log_msg("\t\t> ACK flag setted to 0, assigning a backend...");

                    // Find the index of the backend server with the least connections
                    bit<9> min_r_connections_index;
                    min_r_connections_count(connections_count, min_r_connections_index);

                    // Backed server ID = register index + 2
                    meta.assigned_backend = min_r_connections_index + (bit<9>)2;

                    // Increment the number of connections for the assigned backend
                    r_connections_count.read(connections_count, min_r_connections_index); 
                    r_connections_count.write(min_r_connections_index, connections_count+1);
                    log_msg("\t\t> Backend {} assigned, {} connections.", {meta.assigned_backend, connections_count});
                } else {
                    log_msg("\t\t> ACK flag setted to 1, PACKET DROPPED!");
                    drop();
                }
            } else {
                log_msg("\t\t> SYN flag setted to 0, PACKET DROPPED!");
                drop();
            }
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
        /* TODO 18: Update the packet fields before redirecting the 
         * packet to the client.
         */
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

    apply {  
        /* Check if the ingress port is the one connected to the client. 
         *
         * Verify whether the packet is destined for the Virtual IP 
         * If not, drop the packet.
         * If yes, continue with the ingress logic
         */
        if (hdr.eth.isValid() && hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            if (standard_metadata.ingress_port == CLIENT_PORT_IDX) {
                if (virtual_ip.apply().action_run == is_virtual_ip) {
                    check_backend_assignment();
                }
            }
        } else if (standard_metadata.ingress_port == BACKEND1_PORT_IDX || 
                standard_metadata.ingress_port == BACKEND2_PORT_IDX || 
                standard_metadata.ingress_port == BACKEND3_PORT_IDX ||
                standard_metadata.ingress_port == BACKEND4_PORT_IDX) {
            //todo
        }
    }

        

        

        /* TODO 12: Define the logic to assign a new backend to the connection.
         * You should assign the backend with the minimum number of connections.
         * If there are multiple backends with the same number of connections,
         * you should assign the backend with the lowest index.
         */

        /* TODO 14: If the packet is already assigned, and if the FIN or RST flags are enabled 
         * you should remove the assignment and decrement the number of connections
         * for the backend. Finally, forward the packet to the backend.
        */

        /* TODO 15: Before redirecting the packet from CLIENT to BACKEND, make sure
         * to update the packet fields (IP, MAC, etc.).
         */

        /* TODO 17: If the packet is coming from the other direction, make sure
         * to update the packet fields (IP, MAC, etc.) before redirecting it
         * to the client. The backend_to_vip table is used to get the information
         * about the VIP.
         */
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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