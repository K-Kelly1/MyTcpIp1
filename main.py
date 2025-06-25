from scapy.all import conf, IFACES
import argparse
from typing import Any
from collections import namedtuple
from winpcapy import *


IP_type = b'\x08\x00'


def get_ethernet_frame(mac: str, iface: str) -> Any:
    macs_to_retrieve = ['ff-ff-ff-ff-ff-ff', mac]
    sock = conf.L2socket(iface=iface, promisc=True)

    l2_bytes = None
    while not l2_bytes:
        l2_bytes = sock.recv_raw(1024)[1]

    dst_mac = l2_bytes[0:6].hex('-')
    ether_type = l2_bytes[12:14]

    print(f"The dst mac was: {dst_mac}")

    if dst_mac in macs_to_retrieve:
        return ether_type, l2_bytes[14:]

    return -1


def parse_ip_packet(payload: bytes) -> None:
    pass


def main() -> int:
    parser = argparse.ArgumentParser(prog='main.py', usage='python %(prog)s [options]')
    parser.add_argument('mac', type=str, help='YOUR MAC ADDRESS')
    parser.add_argument('iface', type=str, help='YOUR IFACE')
    args = parser.parse_args()

    result = get_ethernet_frame(args.mac, args.iface)

    if result == -1:
        print("Ethernet frame was not for me!")
        return -1
    elif result[0] == IP_type:
        print("IP payload to handle...")
        parse_ip_packet(result[1])
        return 0


if __name__ == '__main__':
    main()
