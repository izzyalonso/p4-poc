/* -*- P4_16 -*- */
#include <core.p4>
//#include <v1model.p4>
#include <psa.p4>

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
    ip4Addr_t dstIpAddrIn;
    ip4Addr_t dstIpAddrOut;
}

struct empty_metadata_t {
}

struct fwd_metadata_t {
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
    return hdr.ipv4.srcAddr == h2_ip;
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
                in psa_ingress_parser_input_metadata_t istd,
                in empty_metadata_t resubmit_meta,
                in empty_metadata_t recirculate_meta) {

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
        transition parse_tcp;
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(extractCustom(hdr)) {
            true: extract_custom;
            default: generate_custom;
        }
    }

    state generate_custom {
        custom_full_t full = { hdr.ipv4.dstAddr, 32w2 };
        hdr.custom.full = full;
        transition accept;
    }
    
    state extract_custom {
        packet.extract(hdr.custom.full);
        transition accept;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  in    psa_ingress_input_metadata_t  istd,
                  inout psa_ingress_output_metadata_t ostd) {
    action drop() {
        ingress_drop(ostd);
    }
    
    action ipv4_forward(macAddr_t dstMacAddr, ip4Addr_t dstIpAddr) {
        meta.dstIpAddrIn = hdr.ipv4.dstAddr;
        meta.dstIpAddrOut = dstIpAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.dstAddr = dstIpAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
        
        const entries = {
            (     _, h1_ip) : ipv4_forward(h1_mac, h1_ip);
            (     _, h2_ip) : ipv4_forward(h2_mac, h2_ip);
            ( h1_ip, h3_ip) : ipv4_forward(h2_mac, h2_ip);
            ( h2_ip, h3_ip) : ipv4_forward(h3_mac, h3_ip);
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
                 in    psa_egress_input_metadata_t  istd,
                 inout psa_egress_output_metadata_t ostd) {
    InternetChecksum() cs16;
    apply {
        cs16.clear();
        cs16.add({
            /* 16-bit word  0   */ hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            /* 16-bit word  1   */ hdr.ipv4.totalLen,
            /* 16-bit word  2   */ hdr.ipv4.identification,
            /* 16-bit word  3   */ hdr.ipv4.flags, hdr.ipv4.fragOffset,
            /* 16-bit word  4   */ hdr.ipv4.ttl, hdr.ipv4.protocol,
            /* 16-bit word  5 skip hdr.ipv4.hdrChecksum, */
            /* 16-bit words 6-7 */ hdr.ipv4.srcAddr,
            /* 16-bit words 8-9 */ hdr.ipv4.dstAddr
            });
        hdr.ipv4.hdrChecksum = cs16.get();
        
        cs16.clear();
        cs16.subtract(hdr.tcp.checksum);
        cs16.subtract(meta.dstIpAddrIn);
        cs16.add(meta.dstIpAddrOut);
        hdr.tcp.checksum = cs16.get();
        if (!emitCustom(hdr)) {
            custom_empty_t empty = { };
            hdr.custom.empty = empty;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

/*control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
    }
}*/

control IngressDeparserImpl(packet_out packet,
                            out empty_metadata_t clone_i2e_meta,
                            out empty_metadata_t resubmit_meta,
                            out empty_metadata_t normal_meta,
                            inout headers hdr,
                            in metadata meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers hdr,
                        inout metadata user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_metadata_t normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet,
                   out empty_metadata_t clone_e2e_meta,
                   out empty_metadata_t recirculate_meta,
                   inout headers hdr,
                   in metadata meta,
                   in psa_egress_output_metadata_t istd,
                   in psa_egress_deparser_input_metadata_t edstd) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        //packet.emit(hdr.custom);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

IngressPipeline(MyParser(),
                MyIngress(),
                IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(),
               MyEgress(),
               MyDeparser()) ep;
               
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;

/*PSA_Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
//MyComputeChecksum(),
MyDeparser()
) main;*/
