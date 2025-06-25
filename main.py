from scapy.all import conf, IFACES
import argparse
from typing import Any


IP_TYPE = b'\x08\x00'
BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'
RECEIVE_BUFFER_SIZE = 1024


def sniff_ethernet_frame(iface: str) -> Any:
    sock = conf.L2socket(iface=iface, promisc=True)

    frame_in_bytes = None
    while not frame_in_bytes:
        _, frame_in_bytes, _ = sock.recv_raw(RECEIVE_BUFFER_SIZE)

    return frame_in_bytes


def parse_ethernet_frame(frame: bytes):
    dst_mac = frame[0:6].hex(':')
    ether_type = frame[12:14]
    payload = frame[14:]
    return dst_mac, ether_type, payload


def does_for_me(dst_mac: str, my_mac: str) -> bool:
    macs_to_retrieve = [my_mac, BROADCAST_ADDRESS]
    if dst_mac in macs_to_retrieve:
        return True
    return False


def parse_ip_packet(payload: bytes) -> None:
    pass


def main() -> None:
    parser = argparse.ArgumentParser(prog='main.py', usage='python %(prog)s [options]')
    parser.add_argument('mac', type=str, help='YOUR MAC ADDRESS')
    parser.add_argument('iface', type=str, help='YOUR IFACE')
    args = parser.parse_args()

    frame_in_bytes = sniff_ethernet_frame(args.iface)
    dst_mac, ether_type, payload = parse_ethernet_frame(frame_in_bytes)
    if does_for_me(dst_mac, args.mac):
        if ether_type == IP_TYPE:
            parse_ip_packet(payload)
            print(payload)


if __name__ == '__main__':
    main()
