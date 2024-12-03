"""
Parser for IPFIX packet v4 and v6 for RDP template.
"""

import argparse
import ipaddress
import logging
import struct
import sys
import warnings
from datetime import datetime
from pprint import pprint

warnings.filterwarnings("error")

# Remove scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.packet import bind_layers, Packet
from scapy.layers.inet import TCP, UDP
from scapy.utils import PcapReader
from scapy.layers.netflow import ipfix_defragment, NetflowHeader, \
    NetflowHeaderV10, NetflowDataflowsetV9

logging.basicConfig(
    format="{asctime} - {levelname} - {message}",
    datefmt="%H-%M-%S",
    style="{",
    level=logging.INFO
)

bind_layers(UDP, NetflowHeader, dport=4739)
bind_layers(NetflowHeader, NetflowHeaderV10, version=10)

TEMPLATES_PACKET_COUNT = 0
IPFIX_PACKET_COUNT = 0


def get_payload(packet: Packet) -> (bytes, dict):
    """
    The function parses the IPFIX packet header and returns flowsets raw data.

    :param packet: scapy packet
    :return: ipfix_payload: do not parsed IPFIX payload with flowsets in bytes
             parsed ipfix header: dictionary with parsed IPFIX header for packet
    """
    ipfix_defrag = ipfix_defragment(packet)[0]
    logging.debug(f"Print ipfix packet: {ipfix_defrag}")

    # parse netflow header
    netflow_header = ipfix_defrag[NetflowHeader]
    netflow_version = netflow_header.version

    # parse ipfix_header
    ipfix_header = ipfix_defrag[NetflowHeaderV10]
    logging.debug(f"IPFIX Header: {ipfix_header}")
    ipfix_timestamp = ipfix_header.ExportTime
    ipfix_export_time = str(datetime.fromtimestamp(ipfix_timestamp))
    ipfix_flow_sequence = ipfix_header.flowSequence
    ipfix_observation_domain_id = ipfix_header.ObservationDomainID

    # parse ipfix_data
    ipfix_data = ipfix_defrag[NetflowDataflowsetV9]
    ipfix_template_id = ipfix_data.templateID
    ipfix_length = ipfix_data.length
    ipfix_payload = ipfix_data.records[0].fieldValue

    logging.debug(f"IPFIX Payload: {ipfix_payload}")

    ipfix_header_dict = {
        "Netflow version": netflow_version,
        "IPFIX Export Time": ipfix_export_time,
        "IPFIX Flow Sequence": ipfix_flow_sequence,
        "IPFIX Observation Domain ID": ipfix_observation_domain_id,
        "IPFIX Template ID": ipfix_template_id,
        "IPFIX Payload Length": ipfix_length,
    }

    return ipfix_payload, ipfix_header_dict


def parse_flowset_ipv4(flowset: bytes) -> dict:
    """
    Return a dictionary with parsed data for flowset with ipv4 packets.

    :param flowset: flowset raw data from IPFIX packet
    :return: parsed IPFIX flowset dictionary
    """
    ipv4_src_addr, ipv4_dst_addr, protocol, ip_fragment_flags, \
        l4_src_port, l4_dst_port, tcp_flags, icmp_type, ip_ttl, \
        input_snmp, output_snmp, forwarding_status, \
        sampling_packet_space, in_bytes, in_pkts = struct.unpack('!4s4sBBHHHHBIIBIQQ', flowset[:48])

    # RDP special fields
    rdp_extended_forwarding_status, rdp_policy, rdp_rule = struct.unpack('!HLL', flowset[48:])

    # 6 -> TCP proto
    if protocol == 6:
        protocol = f"TCP ({protocol})"
    elif protocol == 17:
        protocol = f"UDP ({protocol})"

    if tcp_flags:
        tcp_flags = str(TCP(flags=tcp_flags).flags)

    ipv4_src_addr = str(ipaddress.IPv4Address(ipv4_src_addr))
    ipv4_dst_addr = str(ipaddress.IPv4Address(ipv4_dst_addr))

    bin_forwarding_status = bin(forwarding_status)
    if forwarding_status & 0x80:
        forwarding_status = f"Dropped ({bin_forwarding_status})"
    elif forwarding_status & 0x40:
        forwarding_status = f"Forward ({bin_forwarding_status})"
    else:
        forwarding_status = f"Unknown ({bin_forwarding_status})"

    ip_fragment_flags = bin(ip_fragment_flags)
    rdp_extended_forwarding_status = bin(rdp_extended_forwarding_status)
    rdp_rule = bin(rdp_rule)
    rdp_policy = bin(rdp_policy)

    flowset_dict = {
        "IPV4_SRC_ADDR": ipv4_src_addr,
        "IPV4_DST_ADDR": ipv4_dst_addr,
        "PROTOCOL": protocol,
        "IP_FRAGMENT_FLAGS": ip_fragment_flags,
        "L4_SRC_PORT": l4_src_port,
        "L4_DST_PORT": l4_dst_port,
        "TCP_FLAGS": tcp_flags,
        "ICMP_TYPE": icmp_type,
        "IP_TTL": ip_ttl,
        "INPUT_SNMP": input_snmp,
        "OUTPUT_SNMP": output_snmp,
        "FORWARDING_STATUS": forwarding_status,
        "SAMPLING_PACKET_SPACE": sampling_packet_space,
        "IN_BYTES": in_bytes,
        "IN_PKTS": in_pkts,
        "RDP_EXTENDED_FORWARDING_STATUS": rdp_extended_forwarding_status,
        "RDP_POLICY": rdp_policy,
        "RDP_RULE": rdp_rule
    }

    return flowset_dict


def parse_flowset_ipv6(flowset: bytes) -> dict:
    """
    Return a dictionary with parsed data for flowset with ipv6 packets.

    :param flowset: flowset raw data from IPFIX packet
    :return: parsed IPFIX flowset dictionary
    """
    ipv6_src_addr, ipv6_dst_addr, protocol, l4_src_port, l4_dst_port, \
        tcp_flags, ipv6_icmp_type, ipv6_icmp_code, ip_ttl, \
        input_snmp, output_snmp, forwarding_status, sampling_packet_space, \
        in_bytes, in_pkts = struct.unpack('!16s16sBHHHBBBIIBLQQ', flowset[:71])

    # RDP special fields
    rdp_extended_forwarding_status, rdp_policy, rdp_rule = struct.unpack('!HLL', flowset[71:])

    # 6 -> TCP proto
    if protocol == 6:
        protocol = f"TCP ({protocol})"
    elif protocol == 17:
        protocol = f"UDP ({protocol})"

    if tcp_flags:
        tcp_flags = str(TCP(flags=tcp_flags).flags)
    ipv6_src_addr = str(ipaddress.IPv6Address(ipv6_src_addr))
    ipv6_dst_addr = str(ipaddress.IPv6Address(ipv6_dst_addr))

    bin_forwarding_status = bin(forwarding_status)
    if forwarding_status & 0x80:
        forwarding_status = f"Dropped ({bin_forwarding_status})"
    elif forwarding_status & 0x40:
        forwarding_status = f"Forward ({bin_forwarding_status})"
    else:
        forwarding_status = f"Unknown ({bin_forwarding_status})"

    rdp_extended_forwarding_status = bin(rdp_extended_forwarding_status)
    rdp_rule = bin(rdp_rule)
    rdp_policy = bin(rdp_policy)

    flowset_dict = {
        "IPV6_SRC_ADDR": ipv6_src_addr,
        "IPV6_DST_ADDR": ipv6_dst_addr,
        "PROTOCOL": protocol,
        "L4_SRC_PORT": l4_src_port,
        "L4_DST_PORT": l4_dst_port,
        "TCP_FLAGS": tcp_flags,
        "IPV6 ICMP Type": ipv6_icmp_type,
        "IPV6 ICMP Code": ipv6_icmp_code,
        "IP_TTL": ip_ttl,
        "INPUT_SNMP": input_snmp,
        "OUTPUT_SNMP": output_snmp,
        "FORWARDING_STATUS": forwarding_status,
        "SAMPLING_PACKET_SPACE": sampling_packet_space,
        "IN_BYTES": in_bytes,
        "IN_PKTS": in_pkts,
        "RDP_EXTENDED_FORWARDING_STATUS": rdp_extended_forwarding_status,
        "RDP_POLICY": rdp_policy,
        "RDP_RULE": rdp_rule
    }

    return flowset_dict


def packet_proccess(packet: Packet) -> dict:
    """

    :param packet: scapy packet
    :return: dictionary with parsed flowsets for this packet
    """
    try:
        if packet.haslayer(NetflowDataflowsetV9):
            flowset_length = 1
            ipv4_flag = False
            ipv6_flag = False

            payload, ipfix_header = get_payload(packet)

            if ipfix_header["IPFIX Template ID"] == 256:
                flowset_length = 58
                ipv4_flag = True
            elif ipfix_header["IPFIX Template ID"] == 257:
                flowset_length = 81
                ipv6_flag = True
            else:
                logging.error("IPFIX Unknown Template ID %d", ipfix_header["IPFIX Template ID"])

            flowsets = len(payload) // flowset_length
            if flowsets % 1 == 0:
                i = 0
                for flowset_number in range(1, flowsets + 1):
                    flowset = payload[i: i + flowset_length]
                    if ipv4_flag:
                        ipfix_header[f'Flowset {flowset_number}'] = parse_flowset_ipv4(flowset)
                    elif ipv6_flag:
                        ipfix_header[f'Flowset {flowset_number}'] = parse_flowset_ipv6(flowset)
                    i += flowset_length
                return ipfix_header
            else:
                logging.error(
                    "The length of the packet payload is not a multiple of 58 (ipv4) or 81 (ipv6)"
                )
    except (SyntaxWarning, ValueError):
        print(f"Packet {count_of_packets} is template")


def main() -> argparse.Namespace:
    """
    Args parser for script.

    :return: args
    """
    parser = argparse.ArgumentParser(description='Parser for ipfix')
    parser.add_argument(
        '--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True
    )
    parser.add_argument(
        '--packet_number', metavar='<packet number>',
        help='packet number want to parse', required=False
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


if __name__ == "__main__":
    args = main()

    count_of_packets: int = 0
    ipfix_packets = []
    packet_number: bool = False

    if args.packet_number:
        packet_number = int(args.packet_number)

    with PcapReader(args.pcap) as pcap_reader:
        for packet in pcap_reader:
            count_of_packets += 1
            if packet.haslayer(NetflowHeader):
                IPFIX_PACKET_COUNT += 1
                parse_packet = packet_proccess(packet)
                if parse_packet:
                    if packet_number:
                        if packet_number != count_of_packets:
                            continue
                    print(f'Packet number: {count_of_packets} in {args.pcap} file')
                    pprint(parse_packet, sort_dicts=False)
                    if packet_number == count_of_packets:
                        break
                else:
                    TEMPLATES_PACKET_COUNT += 1

    print("Template packets count: %d" % TEMPLATES_PACKET_COUNT)
    print("Total IPFIX packet count: %d" % IPFIX_PACKET_COUNT)
