from enum import Enum
from random import randrange

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp

HST_IP = "192.168.12.4"
DST_IP = "192.168.12.14"
SRC_IP = "192.168.12.13"

MAX_SEQ_NUM = 2 ** 32 - 1


class Port(Enum):
    HTTP = 80
    HTTPS = 443
    SSH = 22


def generate_bits(msg: str):
    bit_str = ''
    bytes_seq = bytearray(msg, encoding="utf-8")
    for b in bytes_seq:
        bit_str += f"{format(b, '08b')}."

    print(bit_str)
    return bytes_seq


def forge_packet(msg: str, net_iface: str):
    base_seq = 1000
    mask = b'\xfe'

    bytes_seq = generate_bits(msg)

    for byte in bytes_seq:
        for i, bit_num in range(8):
            encoded_seq = (base_seq + i) & mask
            tcp_p = TCP(sport=randrange(49152, 65535), dport=Port.HTTP, seq=encoded_seq)
            pkt = IP(src=SRC_IP, dst=DST_IP) / tcp_p

            sendp(iface=net_iface, )


if __name__ == "__main__":
    bits = generate_bits("kt")
