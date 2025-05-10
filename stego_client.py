from random import randrange

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp

from session_info import DST_IP, SRC_IP, Port

# 2^32
MAX_TCP_SEQ_NUM = 1 << 32

# 1 byte
OCTET = 8

# 1111 1110
LSB_MASK = int(b'\xfe')


class StegoClient:
    def __init__(self):
        print("Fuck me!")

    def init_tcp_sesh(self):
        pass

    def _generate_bits(self, msg: str):
        bit_str = ''
        bytes_seq = bytearray(msg, encoding="utf-8")
        for b in bytes_seq:
            bit_str += f"{format(b, '08b')}."

        print(bit_str)
        return bytes_seq

    def forge_msg_packets(self, msg: str, net_iface: str):
        base_seq_num = randrange(0, MAX_TCP_SEQ_NUM)

        bytes_seq = self._generate_bits(msg)

        for byte in bytes_seq:
            for i, bit_num in range(OCTET):
                encoded_seq = (base_seq_num + i) & LSB_MASK
                tcp_p = TCP(sport=randrange(49152, 65535), dport=Port.HTTP, seq=encoded_seq)
                pkt = IP(src=SRC_IP, dst=DST_IP) / tcp_p

                sendp(iface=net_iface, )


if __name__ == "__main__":
    pass
