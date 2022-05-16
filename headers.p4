header epic_common_header_t {
    bit<4> version;
    bit<8> qos;
    bit<20> flow_id;
    bit<8> next_hdr;
    bit<8> hdr_len;
    bit<16> payload_len;
    bit<8> path_type;
    bit<2> DT_dst_address_type;
    bit<2> DL_dst_address_len;
    bit<2> ST_src_address_type;
    bit<2> SL_src_address_len;
    bit<16> _rsv;
}

header epic_address_header_t {
    bit<16> dst_isd;
    bit<48> dst_as;
    bit<16> src_isd;
    bit<48> src_as;
    // @FIX: dst_host_addr and src_host_addr may be different
    // than 32 bits; follows the DT/DL/ST/SL fields
    // from the common header
    bit<32> dst_host_addr;
    bit<32> src_host_addr;
    
}

header epic_path_meta_header_t {
    bit<2> curr_inf;
    bit<6> curr_hf;
    bit<6> _rsv;
    bit<6> seg0_len;
    bit<6> seg1_len;
    bit<6> seg2_len;
}

header epic_info_field_header_t {
    bit<6> _rsv;
    bit<1> peering;
    bit<1> construction_direction;
    bit<8> _rsv2;
    bit<16> seg_id;
    bit<32> timestamp;
}

#define HOP_FIELD_SIZE 96
header epic_hop_field_header_t {
    bit<6> _rsv;
    bit<1> cons_ingress_router_alert;
    bit<1> cons_egress_router_alert;
    bit<8> exp_time;
    bit<16> cons_ingress;
    bit<16> cons_egress;
    bit<48> mac;
}

header hop_field_garbage_2_t {
    bit<(2*HOP_FIELD_SIZE)> hop_field_byte_buffer_2;
}

header hop_field_garbage_1_t {
    bit<(HOP_FIELD_SIZE)> hop_field_byte_buffer_1;
}

// @TODO: speak with prof because both info fields and
// hop fields are variable, and how to encode that in P4
// in a sane way
struct epic_path_type_header_t {
    epic_path_meta_header_t meta;
    // There can be between 1 and 3 info fields, they should only
    // be filled if they exist in the packet_in
    epic_info_field_header_t info1;
    epic_info_field_header_t info2;
    epic_info_field_header_t info3;
    // @TODO: there can be between 1 and 64 hop fields,
    // We only need to extract our field, and the rest can be parsed
    // into byte buffers
    // For now I'll only handle 4 hop fields
    hop_field_garbage_2_t hf_garbage_2_before;
    hop_field_garbage_1_t hf_garbage_1_before;
    epic_hop_field_header_t hop_field;
    hop_field_garbage_2_t hf_garbage_2_after;
    hop_field_garbage_1_t hf_garbage_1_after;
}
