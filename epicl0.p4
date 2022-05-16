#include <v1model.p4>
#include <core.p4>
#include "headers.p4"

struct epicl0_header_t {
    epic_common_header_t common;
    epic_address_header_t address;
    epic_path_type_header_t path;
}

struct metadata_t {
    bit<6> number_of_hop_fields;
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
        
        meta.number_of_hop_fields = epic_packet.path.meta.seg0_len +
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
        transition parse_hop_fields_begin;
    }

    state parse_info_field_2 {
        meta.info_fields = 2;
        packet.extract(epic_packet.path.info1);
        packet.extract(epic_packet.path.info2);
        transition parse_hop_fields_begin;
    }

    state parse_info_field_3 {
        meta.info_fields = 3;
        packet.extract(epic_packet.path.info1);
        packet.extract(epic_packet.path.info2);
        packet.extract(epic_packet.path.info3);
        transition parse_hop_fields_begin;
    }

    
    state parse_hop_fields_begin {
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
        transition parse_hop_fields_begin;
    }

    state parse_hop_field {
        packet.extract(epic_packet.path.hop_field);
        meta.garbage_hop_fields = meta.number_of_hop_fields - meta.garbage_hop_fields - 1;
        transition parse_hop_field_trash_after;
    }

    state parse_hop_field_trash_after {
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

    action abort(bit<1> n) {
        mark_to_drop(standard_metadata);
    }

    table hello_world {
        key = {epic_header.common.version: exact;}
        actions = {
            abort;
        }
    }

    apply {
        hello_world.apply();
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
    apply{}
}

V1Switch(EpicL0Parser(), EmptyVerifyChecksum(), EpicL0PipeIngress(), EmptyEgress(), EmptyComputeChecksum(), EmptyDeparser()) main;