from random import randrange

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

from custom_logger import dpi_logger
from session_info import Port, MAGIC_SEQ, CRC8_FUNC, \
    MAGIC_BYTE_LEN, INDEX_BYTE_LEN, DATA_BYTE_LEN, MSG_LENGTH_BYTE_LEN, CRC_BYTE_LEN

MAX_MSG_SIZE = (1 << 16) - 1
LSB_MASK = int(~1)


class StegoClient:
    def __init__(self, clt_ip, srv_ip):
        self._curr_port = randrange(49152, 65535)

        self._clt = clt_ip
        self._srv = srv_ip

    @staticmethod
    def _build_stego_chunk(data_byte: int, index: int):
        # Shift magic byte to prepare space for index byte and append it
        chunk = (MAGIC_SEQ << INDEX_BYTE_LEN) | index
        # Shift magic|index bytes to prepare space for data byte and append it
        chunk = (chunk << DATA_BYTE_LEN) | data_byte

        # Build crc for magic|index|data bytes
        crc = CRC8_FUNC(chunk.to_bytes(MAGIC_BYTE_LEN + INDEX_BYTE_LEN, "big"))

        # Shift magic|index|data bytes to prepare space for crc byte and append it
        chunk = (chunk << CRC_BYTE_LEN) | crc

        return chunk

    def transmit_stego_msg(self, msg: str):
        def send_packet(seq: int):
            try:
                # Prepare lvl 2 layers
                ip_l = IP(src=self._clt, dst=self._srv)
                tcp_l = TCP(sport=self._curr_port, dport=Port.HTTP.value, seq=seq,
                            flags="S")

                # Assemble packet
                init_pkt = ip_l / tcp_l
                send(init_pkt, verbose=False)
                dpi_logger.debug(f"Sent byte {byte} with seq {seq}")

            except Exception as ex:
                dpi_logger.error(f"Error while sending packet: {ex}")

        def send_init_chunk():
            msg_len_in_bits = len(msg.encode("utf-8")) * 8
            if msg_len_in_bits > MAX_MSG_SIZE:
                raise RuntimeError("Message is too long for one transmission. Aborting...")

            init_seq = (MAGIC_SEQ << MSG_LENGTH_BYTE_LEN) | msg_len_in_bits

            # Build crc for magic|len bytes
            crc = CRC8_FUNC(init_seq.to_bytes(MAGIC_BYTE_LEN + MSG_LENGTH_BYTE_LEN, "big"))

            # Assemble full init sequence
            init_seq = (init_seq << CRC_BYTE_LEN) | crc
            send_packet(init_seq)

        msg_bytes = msg.encode("utf-8")
        dpi_logger.info(f"Preparing to transmit message '{msg}' of length {len(msg_bytes)} byte")
        send_init_chunk()

        for i, byte in enumerate(msg_bytes):
            # Build chunk for 1 byte of msg
            encoded_seq = self._build_stego_chunk(byte, i)
            send_packet(encoded_seq)

            dpi_logger.debug(f"Sent byte {byte} with seq {encoded_seq}")


if __name__ == "__main__":
    clt = StegoClient(clt_ip="192.168.12.106", srv_ip="192.168.12.4")
    clt.transmit_stego_msg("hi")
