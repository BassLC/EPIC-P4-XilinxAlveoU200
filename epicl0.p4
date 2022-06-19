#include <v1model.p4>
#include <core.p4>
#include "headers.p4"

#define CPU_PORT 64
typedef bit<9> PortId_t;

struct epicl0_header_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    epic_common_header_t common;
    epic_address_header_t address;
    epic_path_type_header_t path;
}

struct metadata_t {
    bit<6> total_number_of_hop_fields;
    bit<6> garbage_hop_fields;
    bit<2> info_fields;
}

error {
    EpicCommonUnsupportedVersion,
    EpicCommonUnsupportedPathType,
    EpicInvalidNumberOfHopFields,
    EpicInvalidSegmentLengths
}

parser EpicL0Parser(packet_in packet, out epicl0_header_t epic_packet, inout metadata_t meta, inout standard_metadata_t stdmeta) {
    state start {
        transition parse_encapsulating_headers;
    }

    state parse_encapsulating_headers {
        packet.extract(epic_packet.ethernet);
        packet.extract(epic_packet.ipv4);
        packet.extract(epic_packet.udp);
        transition parse_common_header;
    }

    state parse_common_header {
        packet.extract(epic_packet.common);
        verify(epic_packet.common.version == 0, error.EpicCommonUnsupportedVersion);
        verify(epic_packet.common.path_type < 4, error.EpicCommonUnsupportedPathType);
        // @TODO check next_hdr for tcp/udp handling
        // @TODO check DT/ST/DL/SL for address type
        transition parse_address_header;
    }

    state parse_address_header {
        // @TODO check DT/ST/DL/SL for address type
        packet.extract(epic_packet.address);
        // @TODO add verificaion for (dst/src)_(isd/as) from
        // tables (if the isd/as is not in the table, discard
        // the packet)

        transition parse_path_type_header;
    }

    state parse_path_type_header {
        packet.extract(epic_packet.path.meta);

        // Make sure that the sum of the segments' length is smaller than the
        // maximum allowed (64)
        verify((bit<8>)(epic_packet.path.meta.seg0_len) +
            (bit<8>)(epic_packet.path.meta.seg1_len) +
            (bit<8>)(epic_packet.path.meta.seg2_len) <= 64,
            error.EpicInvalidNumberOfHopFields);

        // If segX_len == 0 and Y > X then segY_len can't be bigger than 0
        verify(!(epic_packet.path.meta.seg0_len == 0 && epic_packet.path.meta.seg1_len > 0), error.EpicInvalidSegmentLengths);
        verify(!(epic_packet.path.meta.seg1_len == 0 && epic_packet.path.meta.seg2_len > 0), error.EpicInvalidSegmentLengths);
        
        meta.total_number_of_hop_fields = epic_packet.path.meta.seg0_len +
                                    epic_packet.path.meta.seg1_len +
                                    epic_packet.path.meta.seg2_len;
        
        meta.garbage_hop_fields = epic_packet.path.meta.curr_hf;

        // We assume that at least 1 Info Field exist (meaning that seg0_len > 0).
        // According to the SCION documentation:
        // "segi_len > 0 implies the existance of Info Field i"
        // https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#pathmeta-header
        
        transition select(epic_packet.path.meta.seg1_len,
            epic_packet.path.meta.seg2_len) {
            (0, 0): parse_info_field_1;
            (_, 0): parse_info_field_2;
            default: parse_info_field_3;
        }
    }

    state parse_info_field_1 {
        meta.info_fields = 1;
        packet.extract(epic_packet.path.info1);
        transition parse_hop_fields_start;
    }

    state parse_info_field_2 {
        meta.info_fields = 2;
        packet.extract(epic_packet.path.info1);
        packet.extract(epic_packet.path.info2);
        transition parse_hop_fields_start;
    }

    state parse_info_field_3 {
        meta.info_fields = 3;
        packet.extract(epic_packet.path.info1);
        packet.extract(epic_packet.path.info2);
        packet.extract(epic_packet.path.info3);
        transition parse_hop_fields_start;
    }

    
    state parse_hop_fields_start {
        // @FIXME only handle 4 hop fields
        // We start by extracting the garbage hop fields: hop fields
        // that we do not have a need for. If there are 0 of these
        // then we are in the right place, and we extract the
        // current hop field, since we are going to do operations
        // based on it. After that, we extract the rest of the hop fields
        // again into garbage byte buffers, and we accept the packet.
        
        transition select(meta.garbage_hop_fields) {
            0: parse_hop_field;
            1: parse_hop_field_trash_1_before;
            0x2 &&& 0x2: parse_hop_field_trash_2_before;
        }
    }

    state parse_hop_field_trash_1_before {
        packet.extract(epic_packet.path.hf_garbage_1_before);
        
        meta.garbage_hop_fields = meta.garbage_hop_fields - 1;
        // Next hop field MUST BE the one we want
        transition parse_hop_field;
    }

    state parse_hop_field_trash_2_before {
        packet.extract(epic_packet.path.hf_garbage_2_before);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 2;
        transition parse_hop_fields_start;
    }

    state parse_hop_field {
        packet.extract(epic_packet.path.hop_field);
        meta.garbage_hop_fields = meta.total_number_of_hop_fields - meta.garbage_hop_fields - 1;
        transition parse_hop_field_trash_after;
    }

    state parse_hop_field_trash_after {
        stdmeta.egress_spec = stdmeta.ingress_port;
        transition select(meta.garbage_hop_fields) {
            0: accept;
            1: parse_hop_field_trash_1_after;
            0x2 &&& 0x2: parse_hop_field_trash_2_after;
        }
    }

    state parse_hop_field_trash_1_after {
        packet.extract(epic_packet.path.hf_garbage_1_after);
        // We got to the end of all the hop fields
        transition accept;
    }

    state parse_hop_field_trash_2_after {
        packet.extract(epic_packet.path.hf_garbage_2_after);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 2;
        transition parse_hop_field_trash_after;
    }
    
}

control EmptyVerifyChecksum(inout epicl0_header_t hdr,
    inout metadata_t meta) {
    apply{}
}

control EpicL0PipeIngress(inout epicl0_header_t epic_header,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata) {

    AESMAC() mac;

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }
    
    action fix_packet(PortId_t port) {
        bit<6> number_of_hopfields_in_segment = 0;
        if (epic_header.path.meta.curr_inf == 1) {
            number_of_hopfields_in_segment = epic_header.path.meta.seg0_len;
        } else if (epic_header.path.meta.curr_inf == 2) {
            number_of_hopfields_in_segment = epic_header.path.meta.seg1_len;
        } else {
            number_of_hopfields_in_segment = epic_header.path.meta.seg2_len;
        }

        if (epic_header.path.meta.curr_hf < number_of_hopfields_in_segment) {
            epic_header.path.meta.curr_hf = epic_header.path.meta.curr_hf + 1;
        } else {
            epic_header.path.meta.curr_hf = 0;
            epic_header.path.meta.curr_inf = epic_header.path.meta.curr_inf + 1;
        }

        standard_metadata.egress_spec = port;
    }
    
    table cons_egress_to_port {
        key = {
            epic_header.path.hop_field.cons_egress: exact;
        }

        actions = {
            NoAction;
            fix_packet;
        }

        default_action = NoAction;
        size = 64;
    }
    
    action deliver_packet_locally(PortId_t port) {
        standard_metadata.egress_spec = port;
    }

    // Checks if a packet is for the local AS/ISD. If not, drop the packet.
    table deliver_if_local_packet {
        key = {
            epic_header.address.dst_isd: exact;
            epic_header.address.dst_as: exact;
        }

        actions = {
            deliver_packet_locally;
            drop_packet;
        }

        default_action = drop_packet;
    }

    apply {
        bit<128> output;
        bit<128> mac_key = 1;
        bit<128> data_to_encode = 2;
        mac.mac(mac_key,data_to_encode, output);
        output = 0; // @TODO: change this to use the MAC result

        bit<48> truncated_mac = (bit<48>)output;
        if (truncated_mac == epic_header.path.hop_field.mac) {
            bool no_egress_port = cons_egress_to_port.apply().miss;
            if (no_egress_port) {
                deliver_if_local_packet.apply();
            }
        } else {
            send_to_cpu();
        }
    }
}

control EmptyEgress(inout epicl0_header_t epic_header,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta) {
    apply{}
}

control EmptyComputeChecksum(inout epicl0_header_t hdr,
    inout metadata_t meta) {
    apply{}
}

control EmptyDeparser(packet_out p, in epicl0_header_t hdr){
    apply{
        p.emit(hdr);
    }
}

V1Switch(EpicL0Parser(), EmptyVerifyChecksum(), EpicL0PipeIngress(), EmptyEgress(), EmptyComputeChecksum(), EmptyDeparser()) main;