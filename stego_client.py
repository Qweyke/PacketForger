# NOTE: No socket.socket used! Full packet control with Scapy only
from random import randrange
from time import sleep

from bitarray import bitarray
from scapy.all import send, sniff
from scapy.layers.inet import IP, TCP

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, CRC8_FUNC, BYTE_LEN_IN_BITS, CRC_LEN_BYTE, MSG_LEN_BYTE, \
    MAGIC_LEN_BYTE

MAX_MSG_SIZE = (1 << 16) - 1


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
            return None

        magic_masked = MAGIC_SEQ << (MSG_LEN_BYTE * BYTE_LEN_IN_BITS)
        base_seq = magic_masked | msg_len_in_bits
        crc_int = CRC8_FUNC(base_seq.to_bytes(MSG_LEN_BYTE + MAGIC_LEN_BYTE, "big"))
        full_seq = (base_seq << CRC_LEN_BYTE * BYTE_LEN_IN_BITS) | crc_int
        return full_seq

    def _receive_init_syn_ack(self):
        timeout = 3

        def is_synack_reply(pkt):
            return (
                    pkt.haslayer(TCP)
                    and pkt.haslayer(IP)
                    and pkt[IP].src == self._srv
                    and pkt[IP].dst == self._clt
                    and pkt[TCP].sport == Port.HTTP.value
                    and pkt[TCP].dport == self._curr_port
                    and pkt[TCP].flags == (TcpFlag.SYN.value | TcpFlag.ACK.value)
                    and pkt[TCP].ack == self._seq + 1
            )

        response = sniff(lfilter=is_synack_reply, count=1, timeout=timeout)
        if response:
            pkt = response[0]
            self._seq += 1
            self._ack = pkt[TCP].seq + 1

            ack_pkt = IP(src=self._clt, dst=self._srv) / TCP(
                sport=self._curr_port, dport=Port.HTTP.value,
                seq=self._seq, ack=self._ack, flags=TcpFlag.ACK.value
            )
            send(ack_pkt, verbose=0)
            return True
        else:
            dpi_logger.error("ACK from server wasn't received")
            return False

    def send_stego_msg(self, msg: str, clt_ip: str, srv_ip: str):
        self._clt = clt_ip
        self._srv = srv_ip
        self._curr_port = randrange(49152, 65535)

        init_seq = self._build_init_seq(msg)
        if init_seq is None:
            return

        self._seq = init_seq
        syn_pkt = IP(src=self._clt, dst=self._srv) / TCP(
            sport=self._curr_port, dport=Port.HTTP.value,
            seq=self._seq, flags=TcpFlag.SYN.value
        )
        send(syn_pkt, verbose=0)
        dpi_logger.info("Sent SYN with embedded data")

        if not self._receive_init_syn_ack():
            return

        # Begin covert transmission of message bits in SEQ
        bits = bitarray()
        bits.frombytes(msg.encode("utf-8"))

        for i, bit in enumerate(bits):
            self._seq += 2
            self._seq = (self._seq & ~1) | bit

            pkt = IP(src=self._clt, dst=self._srv) / TCP(
                sport=self._curr_port, dport=Port.HTTP.value,
                seq=self._seq, ack=self._ack,
                flags=TcpFlag.PSH.value | TcpFlag.ACK.value
            )
            send(pkt, verbose=0)
            dpi_logger.debug(f"Sent bit {bit} with seq {self._seq}")
            sleep(0.05)

        dpi_logger.info("Transmission complete")


if __name__ == "__main__":
    clt = StegoClient()
    clt.send_stego_msg("hi", clt_ip="192.168.12.106", srv_ip="192.168.12.4")
