/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<8> TYPE_TCP = 0x6;
const bit<8> TYPE_UDP = 0x11;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_options_t {
    varbit<320> options;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<16> hostLength;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    tcp_t         tcp;
    tcp_options_t tcp_options;
    udp_t         udp;
}

/*
 * Own host addresses, filled in by generator
 */

const bit<32> my_host_ip = 8w10++8w0++8w2++8w2; // 8w10++8w0++8w1++8w1;
const bit<48> my_host_mac = 8w8++8w0++8w0++8w0++8w2++8w0x22; // 8w8++8w0++8w0++8w0++8w1++8w0x11;

/*
 * Next hop address (should be another switch), filled in by generator
 */
 
const bit<48> next_hop_mac = 8w8++8w0++8w0++8w0++8w3++8w0; // 8w8++8w0++8w0++8w0++8w2++8w0;

/*
 * Relevant addresses and ports, filled in by generator
 */





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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.hostLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.tcp_options, (bit<32>)(((bit<32>)hdr.tcp.dataOffset-5)*32));
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
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
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action reroute(macAddr_t dstMacAddr, ip4Addr_t dstIpAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.dstAddr = dstIpAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action forward(macAddr_t dstMacAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action fake_source(macAddr_t dstMacAddr, ip4Addr_t originalDstIpAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.srcAddr = originalDstIpAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: optional;
            hdr.ipv4.dstAddr: optional; 
        }
        actions = {
            reroute;
            forward;
            fake_source;
            drop;
            NoAction;
        }
        default_action = drop();
        
        const entries = {
            ( my_host_ip,          _) : forward(next_hop_mac, 2);
            (          _, my_host_ip) : forward(my_host_mac, 1);
        }
    }
    
    table tcp_routing {
        key = {
            // Source
            hdr.ipv4.srcAddr: optional;
            hdr.tcp.srcPort: optional;
            // Destination
            hdr.ipv4.dstAddr: optional;
            hdr.tcp.dstPort: optional;
        }
        actions = {
            reroute;
            forward;
            fake_source;
            drop;
            NoAction;
        }
        default_action = drop();
        
        const entries = {
            // Incoming traffic rules, identified by source IP and port
            // Type: ( srcIp, srcPort, my_host_ip, _): fake_source()
            
            
            // Outgoing traffic rules, identified by destination IP and port
            // Type: ( my_host_ip, _, dstIp, dstPort): reroute()
            
            
            // All incoming traffic not captured by other rules
            ( _, _, my_host_ip, _) : forward(my_host_mac, 1);
            // All outgoing traffic not captured by other rules
            ( _, _,          _, _) : forward(next_hop_mac, 2);
        }
    }
    
    table udp_routing {
        key = {
            // Source
            hdr.ipv4.srcAddr: optional;
            hdr.tcp.srcPort: optional;
            // Destination
            hdr.ipv4.dstAddr: optional;
            hdr.tcp.dstPort: optional;
        }
        actions = {
            reroute;
            forward;
            fake_source;
            drop;
            NoAction;
        }
        default_action = drop();
        
        const entries = {
            // Incoming traffic rules, identified by source IP and port
            // Type: ( srcIp, srcPort, my_host_ip, _): fake_source()
            
            
            // Outgoing traffic rules, identified by destination IP and port
            // Type: ( my_host_ip, _, dstIp, dstPort): reroute()
            
            
            // All incoming traffic not captured by other rules
            ( _, _, my_host_ip, _) : forward(my_host_mac, 1);
            // All outgoing traffic not captured by other rules
            ( _, _,          _, _) : forward(next_hop_mac, 2);
        }
    }
    
    apply {
        if (hdr.tcp.isValid()) {
            tcp_routing.apply();
        } else if (hdr.udp.isValid()) {
            udp_routing.apply();
        } else if (hdr.ipv4.isValid()) {
            // Fallback for non TCP or UDP traffic
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { }
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
        
        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.hostLength,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
                hdr.tcp.window,
                hdr.tcp.urgentPtr,
                hdr.tcp_options.options
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16
        );
        
        update_checksum_with_payload(
            hdr.udp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.hostLength,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length
            },
            hdr.udp.checksum,
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
        packet.emit(hdr.tcp_options);
        packet.emit(hdr.udp);
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
