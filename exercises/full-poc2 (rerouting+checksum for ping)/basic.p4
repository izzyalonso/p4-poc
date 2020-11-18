/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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

header custom_full_t {
    bit<32> originalDst;
    bit<32> word2;
}

header custom_empty_t {
    // Empty
}

header_union custom_t {
    custom_full_t full;
    custom_empty_t empty;
}

struct metadata {
    bit<1> rerouted;
    ip4Addr_t dstIpAddrIn;
    ip4Addr_t dstIpAddrOut;
    bit<16> tcpLength;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    custom_t     custom;
}

/*
 * Address functions
 */

bit<32> ip_address(in bit<8> s1, in bit<8> s2, in bit<8> s3, in bit<8> s4) {
    return s1++s2++s3++s4;
}

bit<48> mac_address(in bit<8> s1, in bit<8> s2, in bit<8> s3, in bit<8> s4, in bit<8> s5, in bit<8> s6) {
    return s1++s2++s3++s4++s5++s6;
}

/*
 * Host addresses
 */

const bit<32> h1_ip = 8w10++8w0++8w1++8w1;
const bit<32> h2_ip = 8w10++8w0++8w2++8w2;
const bit<32> h3_ip = 8w10++8w0++8w3++8w3;
 
const bit<48> h1_mac = 8w8++8w0++8w0++8w0++8w1++8w0x11;
const bit<48> h2_mac = 8w8++8w0++8w0++8w0++8w2++8w0x22;
const bit<48> h3_mac = 8w8++8w0++8w0++8w0++8w3++8w0x33;

/*
 * Utility
 */

bool extractCustom(in headers hdr) {
    //return hdr.ipv4.srcAddr == h2_ip;
    return false;
}

bool generateCustom(in headers hdr) {
    return hdr.ipv4.srcAddr == h1_ip && hdr.ipv4.dstAddr == h3_ip || hdr.ipv4.srcAddr == h3_ip && hdr.ipv4.dstAddr == h1_ip;
}

bool emitCustom(in headers hdr) {
    return hdr.ipv4.srcAddr != h2_ip;
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

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition parse_tcp;
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(generateCustom(hdr)) {
            true: generate_custom;
            default: accept;
        }
    }
    
    state generate_custom {
        hdr.custom.full = { hdr.ipv4.srcAddr, 32w2 };
        transition accept;
    }
    
    state parse_custom {
        packet.extract(hdr.custom.full);
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
        meta.dstIpAddrIn = hdr.ipv4.dstAddr;
        meta.dstIpAddrOut = dstIpAddr;
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
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            reroute;
            forward;
            fake_source;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
        
        const entries = {
            ( h3_ip, h1_ip) : reroute(h2_mac, h2_ip, 2);
            ( h2_ip, h1_ip) : fake_source(h1_mac, h3_ip, 1);
            (     _, h2_ip) : forward(h2_mac, 2);
            ( h1_ip, h3_ip) : reroute(h2_mac, h2_ip, 2);
            ( h2_ip, h3_ip) : fake_source(h3_mac, h1_ip, 3);
        }
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
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
    apply {
        if (!emitCustom(hdr)) {
            custom_empty_t empty = { };
            hdr.custom.empty = empty;
        }
    }
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
                meta.tcpLength,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
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
        // Always emit, may be empty
        packet.emit(hdr.custom);
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
