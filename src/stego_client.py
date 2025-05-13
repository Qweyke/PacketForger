from random import randrange, randint

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

from custom_logger import dpi_logger
from session_info import DATA_BYTE_LEN
from session_info import Port, MAGIC_SEQ, CRC8_FUNC, \
    MAGIC_BYTE_LEN, MSG_LENGTH_BYTE_LEN, CRC_BYTE_LEN, BASE_BYTE_LEN

MAX_MSG_SIZE = (1 << 16) - 1
LSB_MASK = int(~1)


class StegoClient:
    def __init__(self, clt_ip, srv_ip):
        self._curr_port = randrange(49152, 65535)

        self._clt = clt_ip
        self._srv = srv_ip

    def _send_packet(self, seq: int):
        try:
            # Prepare lvl 2 layers
            ip_l = IP(src=self._clt, dst=self._srv)
            tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=seq,
                        flags="S")

            # Assemble packet
            init_pkt = ip_l / tcp_l
            send(init_pkt, verbose=False)
            dpi_logger.debug(f"Packet with sequence {seq} sent")

        except Exception as ex:
            dpi_logger.error(f"Error while sending packet: {ex}")

    def transmit_stego_msg(self, msg: str):
        def build_and_send_init_chunk():
            msg_len_in_bits = len(msg.encode("utf-8")) * 8
            if msg_len_in_bits > MAX_MSG_SIZE:
                raise RuntimeError("Message is too long for one transmission. Aborting...")

            init_seq = (MAGIC_SEQ << MSG_LENGTH_BYTE_LEN) | msg_len_in_bits

            # Build crc for magic|len bytes
            crc = CRC8_FUNC(init_seq.to_bytes(MAGIC_BYTE_LEN + MSG_LENGTH_BYTE_LEN, "big"))

            # Assemble full init sequence
            init_seq = (init_seq << CRC_BYTE_LEN) | crc
            self._send_packet(init_seq)

        def build_data_chunk(data_byte: int):
            # Shift magic byte to prepare space for index byte and append it
            start_bytes = randint(0, 0xFFFF)

            # Shift magic|index bytes to prepare space for data byte and append it
            chunk = (start_bytes << DATA_BYTE_LEN) | data_byte

            # Build crc for magic|index|data bytes
            crc = CRC8_FUNC(chunk.to_bytes(BASE_BYTE_LEN + DATA_BYTE_LEN, "big"))

            # Shift magic|index|data bytes to prepare space for crc byte and append it
            chunk = (chunk << CRC_BYTE_LEN) | crc

            return chunk

        msg_bytes = msg.encode("utf-8")
        dpi_logger.info(f"Preparing to transmit message '{msg}' of length {len(msg_bytes)} byte")
        build_and_send_init_chunk()

        for i, byte in enumerate(msg_bytes):
            # Build chunk for 1 byte of msg
            encoded_seq = build_data_chunk(byte)
            self._send_packet(encoded_seq)

            dpi_logger.debug(f"Sent byte[{i}] '{byte}' with seq {encoded_seq}")


if __name__ == "__main__":
    clt = StegoClient(clt_ip="192.168.12.106", srv_ip="192.168.12.4")
    clt.transmit_stego_msg("hi")
