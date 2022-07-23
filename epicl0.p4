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
    bool last_hopfield_present;
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
        
        meta.garbage_hop_fields = epic_packet.path.meta.curr_hf - 1;
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
        // We start by extracting the garbage hop fields: hop fields
        // that we do not have a need for. If there are 0 of these
        // then we are in the right place, and we extract the
        // current hop field, since we are going to do operations
        // based on it. After that, we extract the rest of the hop fields
        // again into garbage byte buffers, and we accept the packet.

        transition select(epic_packet.path.meta.curr_hf, meta.garbage_hop_fields) {
            (0, _): parse_one_hop_field;
            (_, 0): parse_hop_field;
            (_, 16 .. 31): parse_hop_field_trash_16_before;
            (_, 8 .. 15): parse_hop_field_trash_8_before;
            (_, 4 .. 7): parse_hop_field_trash_4_before;
            (_, 2 .. 3): parse_hop_field_trash_2_before;
            (_, 1): parse_hop_field_trash_1_before;
        }
    }

    state parse_one_hop_field {
        packet.extract(epic_packet.path.hop_field_curr);
        meta.last_hopfield_present = false;

        meta.garbage_hop_fields = meta.total_number_of_hop_fields - epic_packet.path.meta.curr_hf - 1;
        transition parse_hop_field_trash_after;
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

    state parse_hop_field_trash_4_before {
        packet.extract(epic_packet.path.hf_garbage_4_before);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 4;
        transition parse_hop_fields_start;
    }

    state parse_hop_field_trash_8_before {
        packet.extract(epic_packet.path.hf_garbage_8_before);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 8;
        transition parse_hop_fields_start;
    }

    state parse_hop_field_trash_16_before {
        packet.extract(epic_packet.path.hf_garbage_16_before);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 16;
        transition parse_hop_fields_start;
    }

    state parse_hop_field {
        packet.extract(epic_packet.path.hop_field_last);
        packet.extract(epic_packet.path.hop_field_curr);
        meta.last_hopfield_present = true;

        meta.garbage_hop_fields = meta.total_number_of_hop_fields - epic_packet.path.meta.curr_hf - 1;
        transition parse_hop_field_trash_after;
    }

    state parse_hop_field_trash_after {
        transition select(meta.garbage_hop_fields) {
            0: accept;
            1: parse_hop_field_trash_1_after;
            2 .. 3: parse_hop_field_trash_2_after;
            4 .. 7: parse_hop_field_trash_4_after;
            8 .. 15: parse_hop_field_trash_8_after;
            15 .. 31: parse_hop_field_trash_16_after;
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
    
    state parse_hop_field_trash_4_after {
        packet.extract(epic_packet.path.hf_garbage_4_after);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 4;
        transition parse_hop_field_trash_after;
    }

    state parse_hop_field_trash_8_after {
        packet.extract(epic_packet.path.hf_garbage_8_after);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 8;
        transition parse_hop_field_trash_after;
    }

    state parse_hop_field_trash_16_after {
        packet.extract(epic_packet.path.hf_garbage_16_after);
        meta.garbage_hop_fields = meta.garbage_hop_fields - 16;
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
    register<bit<128>>(1) mac_key_reg;

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action epicl0_get_data_block(out bit<128> data_to_encode) {
        data_to_encode = 0;
        bit<16> beta_i = 0;
        bit<32> timestamp = 0;
        if (epic_header.path.meta.curr_inf == 0) {
            beta_i = epic_header.path.info1.seg_id;
            timestamp = epic_header.path.info1.timestamp;
        } else if (epic_header.path.meta.curr_inf == 1) {
            beta_i = epic_header.path.info2.seg_id;
            timestamp = epic_header.path.info2.timestamp;
        } else {
            beta_i = epic_header.path.info3.seg_id;
            timestamp = epic_header.path.info3.timestamp;
        }
        data_to_encode[31:16] = beta_i;
        data_to_encode[63:32] = timestamp;
        data_to_encode[79:72] = epic_header.path.hop_field_curr.exp_time;
        data_to_encode[95:80] = epic_header.path.hop_field_curr.cons_ingress;
        data_to_encode[111:96] = epic_header.path.hop_field_curr.cons_egress;
    }

    // action epicl1_get_data_block(out bit<128> data_to_encode) {
    //     data_to_encode = 0;
    // }
    
    action fix_packet(PortId_t port) {
        bit<6> number_of_hopfields_in_segment = 0;
        if (epic_header.path.meta.curr_inf == 0) {
            number_of_hopfields_in_segment = epic_header.path.meta.seg0_len;
        } else if (epic_header.path.meta.curr_inf == 1) {
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
            epic_header.path.hop_field_curr.cons_egress: exact;
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

    table check_ingress_port {
        key = {
            epic_header.path.hop_field_last.cons_egress: exact;
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
        }

        default_action = NoAction;
    }

    apply {
        mac_key_reg.write(0, 12345);
        if (standard_metadata.parser_error != error.NoError) {
            drop_packet();
        } else {
            // standard_metadata.egress_spec = standard_metadata.ingress_port;
            bool skip_processing = false;
            if (meta.last_hopfield_present) {
                bool ingress_port_is_invalid = check_ingress_port.apply().miss;

                if (ingress_port_is_invalid) {
                    drop_packet();
                    skip_processing = true;
                }
            }

            if (!skip_processing) {
                bit<128> mac_key;
                mac_key_reg.read(mac_key, 0);

                bit<128> data_to_encode;
                epicl0_get_data_block(data_to_encode);

                bit<128> output;
                mac.mac(mac_key, data_to_encode, output);
                output = 0; // @TODO: change this to use the MAC result

                bit<48> truncated_mac = (bit<48>)output;
                if (truncated_mac == epic_header.path.hop_field_curr.mac) {
                    bool no_egress_port = cons_egress_to_port.apply().miss;
                    if (no_egress_port) {
                        deliver_if_local_packet.apply();
                    }
                } else {
                    send_to_cpu();
                }
            }
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