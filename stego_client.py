from random import randrange

from bitarray import bitarray
from bitarray.util import int2ba, ba2int
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, CRC8_FUNC, BYTE_LEN_IN_BITS, MAGIC_LEN_BYTE, \
    CRC_LEN_BYTE, MSG_LEN_BYTE

# 2^32
MAX_TCP_SEQ_NUM = 1 << 32
# 1111 1110
LSB_MASK = int(~1)


class StegoClient:

    def __init__(self):
        self._iface = None
        self._curr_port = None

    def _generate_bits(self, msg: str) -> bitarray:
        bytes_seq = bytearray(msg, encoding="utf-8")
        bits_seq = bitarray()
        bits_seq.frombytes(bytes_seq)
        print(bits_seq.to01())
        return bits_seq

    def _build_init_seq(self, msg_len_bits: bitarray) -> int | None:
        # if len(msg_len_bits) > TCP_HEADER_SEQ_LEN_BYTE - MAGIC_LEN_BYTE - CRC_LEN_BYTE:
        #     dpi_logger.warning("Msg is too long for one session. Aborting transmission")
        #     return

        dpi_logger.info(f"Stego msg length: {msg_len_bits}")

        # Prepare all parts, by shifting bits to their places
        magic_masked = MAGIC_SEQ << ((MSG_LEN_BYTE + CRC_LEN_BYTE) * BYTE_LEN_IN_BITS)
        dpi_logger.warning(
            f"Magic masked: {magic_masked}, bits: {int2ba(magic_masked)}, len {len(int2ba(magic_masked))} ")

        msg_len_masked = ba2int(msg_len_bits) << CRC_LEN_BYTE * BYTE_LEN_IN_BITS
        dpi_logger.warning(
            f"Msg len masked: {msg_len_masked}, bits: {int2ba(msg_len_masked)}, len {len(int2ba(msg_len_masked))}")

        # Calculate CRC for base sequence, no shift needed
        magic_len_in_bytes = (magic_masked | msg_len_masked).to_bytes(MAGIC_LEN_BYTE + MSG_LEN_BYTE, "big")
        crc_int = CRC8_FUNC(magic_len_in_bytes)

        dpi_logger.warning(f"CRC: {crc_int}, bits {int2ba(crc_int)}, len {len(int2ba(crc_int))}")

        full_seq = magic_masked | msg_len_masked | crc_int
        full_seq &= 0xFFFF
        dpi_logger.warning(f"Full seq: {full_seq}, bits: {int2ba(full_seq)}")

        return

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

    def send_stego_msg(self, msg: str, src_ip: str, dst_ip: str):
        # self._iface = search_for_ifaces()
        self._curr_port = randrange(49152, 65535)

        # Count msg len and transmit it
        msg_len_bits = int2ba(len(msg.encode("utf-8")) * 8)
        init_seq = self._build_init_seq(msg_len_bits)

        if init_seq:
            tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=init_seq, flags=TcpFlag.SYN.value)
            # Concatenate layers
            pkt = IP(src=src_ip, dst=dst_ip) / tcp_l
            # Send pack from layer 3
            send(pkt)

        # # Transmit msg
        # msg_bits_seq = self._generate_bits(msg)


if __name__ == "__main__":
    clt = StegoClient()
    clt.send_stego_msg("pipa", src_ip="192.168.12.106", dst_ip="192.168.12.4")
