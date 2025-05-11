from random import randrange

from bitarray import bitarray
from bitarray.util import int2ba
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sendp

from custom_logger import dpi_logger
from session_info import Port, MAGIC_SEQ_LEN, CRC, TCP_HEADER_SEQ_LEN, CRC_LEN, HST_IP, SRV_IP, TcpFlag, CRC4_FUNC

# 2^32
MAX_TCP_SEQ_NUM = 1 << 32
# 1111 1110
LSB_MASK = int(~1)


class StegoClient:

    def __init__(self):
        self._iface = None
        self._curr_port = None

    def init_tcp_sesh(self):
        pass

    def _generate_bits(self, msg: str) -> bitarray:
        bytes_seq = bytearray(msg, encoding="utf-8")
        bits_seq = bitarray()
        bits_seq.frombytes(bytes_seq)
        print(bits_seq.to01())
        return bits_seq

    def _build_init_seq(self, stego_msg_len: bitarray) -> int | None:
        if len(stego_msg_len) > TCP_HEADER_SEQ_LEN - MAGIC_SEQ_LEN - CRC:
            dpi_logger.warning("Msg is too long for one session")
            return

        seq_base = (MAGIC_SEQ_LEN << (TCP_HEADER_SEQ_LEN - MAGIC_SEQ_LEN)) | (len(stego_msg_len) << CRC_LEN)

        crc_value = CRC4_FUNC(seq_base.tobytes())

        return seq_base | crc_value

    # def _send_bit(self, bit: int):
    #
    #     i = randrange(1, 20)
    #     encoded_seq = (MAGIC_SEQ + i) & LSB_MASK
    #     tcp_p = TCP(sport=randrange(49152, 65535), dport=Port.HTTP, seq=encoded_seq)
    #     pkt = IP(src=SRC_IP, dst=DST_IP) / tcp_p
    #
    #     sendp(iface=net_iface, )
    #
    #     pass

    def send_stego_msg(self, msg: str, net_iface_name: str):
        self._iface = net_iface_name
        self._curr_port = randrange(49152, 65535)

        # Count msg len and transmit it
        msg_len_seq = int2ba(len(msg.encode("utf-8")) * 8)
        init_seq = self._build_init_seq(msg_len_seq)
        if init_seq:
            tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP, seq=init_seq, flags=TcpFlag.SYN)
            pkt = IP(src=HST_IP, dst=SRV_IP) / tcp_l
            sendp(iface=self._iface, x=pkt)

        # # Transmit msg
        # msg_bits_seq = self._generate_bits(msg)


if __name__ == "__main__":
    pass
