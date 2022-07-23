#! /usr/bin/env python3

from scapy.all import *
from scapy import fields
from ipaddress import IPv4Address
import argparse

# EPIC/SCION Common Header
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|      QoS      |                FlowID                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    NextHdr    |    HdrLen     |          PayloadLen           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    PathType   |DT |DL |ST |SL |              RSV              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# In ScaPy, never use Bytefields together with BitFields
# See: https://github.com/secdev/scapy/issues/756#issuecomment-321573925
# > It is not a bug, when you use BitFields, you must have a continuous total
# > number of bits that is a multiple of 8, to create full bytes.
# > The solution, as you mention it, is to use BitFields with length 8 to
# > replace ByteFields.
def __generate_epicl0_common_header(header_len, payload_len):
    return [
        fields.BitField("Version", 0, 4),
        fields.BitField("QoS", 0, 8),
        fields.BitField("FlowID", 0, 20),
        fields.BitField("NextHdr", 17, 8),  # 17 = Packet load is UDP
        fields.BitField("HdrLen", header_len, 8),
        fields.BitField("PayloadLen", payload_len, 16),
        fields.BitField("PathType", 3, 8),  # 3 is EPIC Path Type

        # @FIX: Both DT/DL and ST/SL can be different,
        # we assume they are always IPv4
        # Maybe change this into a BitFieldLen?
        fields.BitField("DT", 0, 2),
        fields.BitField("DL", 0, 2),
        fields.BitField("ST", 0, 2),
        fields.BitField("SL", 0, 2),
        fields.BitField("__ReservedCommon", 0, 16),
    ]


# SCION/EPIC Address Header
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |            DstISD             |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# |                             DstAS                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |            SrcISD             |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# |                             SrcAS                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    DstHostAddr (variable Len)                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    SrcHostAddr (variable Len)                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


def __generate_epicl0_address_header(dst_isd, dst_as, dst_host_addr, src_isd,
                                     src_as, src_host_addr):
    return [
        fields.BitField("DstISD", dst_isd, 16),
        fields.BitField("DstAS", dst_as, 48),
        fields.BitField("SrcISD", src_isd, 16),
        fields.BitField("SrcAS", src_as, 48),
        # @FIX: for now we assume that addresses are all IPv4
        fields.IPField("DstHostAddr", dst_host_addr),
        fields.IPField("SrcHostAddr", src_host_addr),
    ]


#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | C |  CurrHF   |    RSV    |  Seg0Len  |  Seg1Len  |  Seg2Len  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
def __generate_epicl0_path_meta_header(current_info_field, current_hop_field,
                                       seg0_len, seg1_len, seg2_len):
    return [
        fields.BitField("CurrInf", current_info_field, 2),
        fields.BitField("CurrHF", current_hop_field, 6),
        fields.BitField("__ReservedPathMeta", 0, 6),
        fields.BitField("Seg0Len", seg0_len, 6),
        fields.BitField("Seg1Len", seg1_len, 6),
        fields.BitField("Seg2Len", seg2_len, 6),
    ]


#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |r r r r r r P C|      RSV      |             SegID             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Timestamp                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
def __generate_epicl0_info_field(seg_id, time_stamp):
    return [
        fields.BitField("__ReservedInfo", 0, 6),
        fields.BitField("PeeringFlag", 0, 1),
        fields.BitField("ConstructionDirectionFlag", 0, 1),
        fields.BitField("__ReservedInfo2", 0, 8),
        fields.BitField("SegID", seg_id, 16),
        fields.BitField("Timestamp", time_stamp, 32),
    ]


#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |r r r r r r I E|    ExpTime    |           ConsIngress         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |        ConsEgress             |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# |                              MAC                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
def __generate_epicl0_hop_field(exp_time, cons_ingress, cons_egress, mac):
    return [
        fields.BitField("__ReservedHopField", 0, 6),
        fields.BitField("I", 0, 1),
        fields.BitField("E", 0, 1),
        fields.BitField("ExpTime", exp_time, 8),
        fields.BitField("ConsIngress", cons_ingress, 16),
        fields.BitField("ConsEgress", cons_egress, 16),
        fields.BitField("MAC", mac, 48),
    ]


def _generate_epicl0_empty_packet():
    """Generate an empty, simple Epic L0 packet."""

    common = __generate_epicl0_common_header(header_len=15, payload_len=0)
    address = __generate_epicl0_address_header(90, 91, IPv4Address("0.0.0.0"),
                                               70, 71, IPv4Address("1.1.1.1"))
    path_meta = __generate_epicl0_path_meta_header(0, 0, 6, 0, 0)
    info_field = __generate_epicl0_info_field(65, 123456789)
    hop_fields = []
    for i in range(7):
        hop_fields += __generate_epicl0_hop_field(0, 0, 0, i)
    return common + address + path_meta + info_field + hop_fields


class EPICL0(Packet):
    name = "epicL0"
    fields_desc = _generate_epicl0_empty_packet()


def main():
    parser = argparse.ArgumentParser(description="Generate EPICL0 packets")

    parser.add_argument("--dst-addr",
                        type=str,
                        dest="dst_addr",
                        required=True,
                        help="IPv4 Destination Address")

    parser.add_argument("--src-addr",
                        type=str,
                        dest="src_addr",
                        required=True,
                        help="IPv4 Source Address")

    parser.add_argument("--iface",
                        type=str,
                        dest="iface",
                        required=True,
                        help="Interface")

    args = parser.parse_args()
    print(args.dst_addr)
    pkt = Ether() / IP(src=args.src_addr, dst=args.dst_addr) / UDP() / EPICL0(
        DstHostAddr=IPv4Address(args.dst_addr),
        SrcHostAddr=IPv4Address(args.src_addr)) / "AAAAA"

    sendp(pkt, iface=args.iface)


if __name__ == '__main__':
    main()
