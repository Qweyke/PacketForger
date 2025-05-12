from random import randrange

from bitarray import bitarray
from bitarray.util import int2ba
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sniff

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, CRC8_FUNC, BYTE_LEN_IN_BITS, CRC_LEN_BYTE, MSG_LEN_BYTE, \
    MAGIC_LEN_BYTE

MAX_MSG_SIZE = (1 << 16) - 1
# 1111 1110
LSB_MASK = int(~1)


class StegoClient:

    def __init__(self):
        self._iface = None
        self._curr_port = None

        self._clt = None
        self._srv = None

        self._seq = None
        self._ack = None

    def _build_init_seq(self, msg: str) -> int | None:

        msg_len_in_bits = len(msg.encode("utf-8")) * BYTE_LEN_IN_BITS
        dpi_logger.info(f"Preparing to transmit message '{msg}' of length {msg_len_in_bits} bit")

        if msg_len_in_bits > MAX_MSG_SIZE:
            dpi_logger.warning("Message is too long for one transmission. Aborting...")
            return False

        # Shift magic num bits to it's place in first 8 bits
        magic_masked = MAGIC_SEQ << (MSG_LEN_BYTE * BYTE_LEN_IN_BITS)
        dpi_logger.debug(
            f"Magic converted: {int2ba(magic_masked)}, len {len(int2ba(magic_masked))}. Magic initial: {int2ba(MAGIC_SEQ)}, len {len(int2ba(MAGIC_SEQ))}")

        # Assemble first 8 and middle 16 bits
        base_seq = magic_masked | msg_len_in_bits
        # Calculate CRC for base sequence, no shift needed
        crc_int = CRC8_FUNC(base_seq.to_bytes(MSG_LEN_BYTE + MAGIC_LEN_BYTE, "big"))

        dpi_logger.debug(f"CRC: {crc_int}, bits {int2ba(crc_int)}, len {len(int2ba(crc_int))}")

        # Assemble full init TCP sequence
        full_seq = (base_seq << CRC_LEN_BYTE * BYTE_LEN_IN_BITS) | crc_int
        dpi_logger.debug(f"Full seq: {full_seq}, bits: {int2ba(full_seq)}, len {len(int2ba(full_seq))}")

        return full_seq

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

    def _receive_init_syn_ack(self):
        timeout = 3

        def is_synack_reply(packet):
            if (
                    packet.haslayer(TCP)
                    and packet.haslayer(IP)
                    and packet[IP].src == self._srv
                    and packet[IP].dst == self._clt
                    and packet[TCP].sport == Port.HTTP.value
                    and packet[TCP].dport == self._curr_port
                    and packet[TCP].flags == TcpFlag.SYN.value | TcpFlag.ACK.value
                    and packet[TCP].ack == self._seq + 1
            ): return True

        # Wait for srv response
        response = sniff(lfilter=is_synack_reply, count=1, timeout=timeout)

        if response:
            pkt = response[0]
            dpi_logger.debug(f"Got SYN-ACK. SEQ = {pkt[TCP].seq}, ACK = {pkt[TCP].ack}")

            self._seq += 1
            tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=self._seq, ack=pkt[TCP].ack + 1,
                        flags=TcpFlag.ACK.value)
            # Concatenate layers
            ack_pkt = IP(src=self._clt, dst=self._srv) / tcp_l
            # Send pack from layer 3
            send(ack_pkt)
            return True

        else:
            dpi_logger.error(f"ACK from server wasn't received after timeout '{timeout}' secs")
            return False

    # def _start_transmission(self, msg):
    #     self._seq = init_seq
    #     tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=self._seq, flags=TcpFlag.SYN.value)
    #     # Concatenate layers
    #     init_pkt = IP(src=src_ip, dst=dst_ip) / tcp_l
    #     # Send pack from layer 3
    #     send(init_pkt)

    def send_stego_msg(self, msg: str, clt_ip: str, srv_ip: str):
        self._clt = clt_ip
        self._srv = srv_ip
        # self._iface = search_for_ifaces()
        self._curr_port = randrange(49152, 65535)

        # Count msg len and transmit it as bit seq-s
        init_seq = self._build_init_seq(msg)
        if init_seq:
            self._seq = init_seq
            tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=self._seq, flags=TcpFlag.SYN.value)
            # Concatenate layers
            init_pkt = IP(src=self._clt, dst=self._srv) / tcp_l
            # Send pack from layer 3
            send(init_pkt)

        if self._receive_init_syn_ack():
            dpi_logger.info("Start transmission!")
            bits_seq = bitarray()
            bits_seq.frombytes(msg.encode("utf-8"))

            for i, bit in enumerate(bits_seq):
                # Устанавливаем LSB в base_seq
                self._seq += i * 2
                if bit == 1:
                    self._seq |= bit
                else:
                    self._seq &= ~1

                tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=self._seq,
                            flags=TcpFlag.PSH.value | TcpFlag.ACK.value)
                # Concatenate layers
                init_pkt = IP(src=self._clt, dst=self._srv) / tcp_l
                # Send pack from layer 3
                send(init_pkt)

        # # Transmit msg
        # msg_bits_seq = self._generate_bits(msg)


if __name__ == "__main__":
    clt = StegoClient()
    clt.send_stego_msg("hi", clt_ip="192.168.12.106", srv_ip="192.168.12.4")
