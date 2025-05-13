from scapy.all import sniff
from scapy.config import conf
from scapy.layers.inet import TCP
from scapy.packet import Packet

from custom_logger import dpi_logger
from session_info import Port, MAGIC_SEQ, search_for_ifaces, CRC8_FUNC, TCP_SEQ_BYTE_LEN, \
    MAGIC_BYTE_LEN, MSG_LENGTH_BYTE_LEN, CRC_BYTE_LEN

conf.debug_dissector = 2

# 2^32 - 1
MAX_TCP_SEQ_NUM = (1 << 32) - 1

DATA_SIZE_IN_BYTES = 2048


class StegoServer:
    def __init__(self, clt_ip, srv_ip):
        self._srv_ip = srv_ip
        self._clt_ip = clt_ip

        self._transmission_active = False
        self._received_bytes = bytearray()
        self._num_bytes_to_receive = 0

    def _check_for_transmission_request(self, seq_num):

        def trans_start_inited() -> bool:
            magic = (seq_num >> (TCP_SEQ_BYTE_LEN - MAGIC_BYTE_LEN)) & 0xFF
            if magic != MAGIC_SEQ:
                dpi_logger.debug("No magic detected")
                return False

            seq_base = (seq_num >> CRC_BYTE_LEN) & 0xFFFFFF
            crc_calculated = CRC8_FUNC(seq_base.to_bytes(MAGIC_BYTE_LEN + MSG_LENGTH_BYTE_LEN, "big"))
            crc_received = seq_num & 0xFF

            if crc_calculated != crc_received:
                dpi_logger.debug("Init CRC is wrong")
                return False

            return True

        if trans_start_inited():
            data_len = (seq_num >> CRC_BYTE_LEN) & 0xFFFF
            dpi_logger.warning(f"Hidden transmission detected. Receiving message of length {data_len}")
            self._num_bytes_to_receive = data_len
            self._transmission_active = True


        else:
            dpi_logger.debug("Trash packet. Skipping...")

    def _handle_data_in_packet(self, seq_num):
        seq_base = (seq_num >> CRC_BYTE_LEN) & 0xFFFFFF
        crc_calculated = CRC8_FUNC(seq_base.to_bytes(TCP_SEQ_BYTE_LEN - CRC_BYTE_LEN, "big"))
        crc_received = seq_num & 0xFF

        if crc_calculated != crc_received:
            dpi_logger.debug("Data chunk CRC is wrong")
            return False

        data_byte = (seq_num >> CRC_BYTE_LEN) & 0xFF
        self._received_bytes.append(data_byte)

    def _refresh_server_state(self):
        self._transmission_active = False
        self._received_bytes = bytearray()
        self._num_bytes_to_receive = 0

    def _handle_stego_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            tcp_seq = packet[TCP].seq
            dpi_logger.debug(f"Received a packet: {packet.summary()}")
            dpi_logger.debug(f"TCP sequence: {tcp_seq}")

            if self._transmission_active:
                self._handle_data_in_packet(tcp_seq)

                if self._num_bytes_to_receive == len(self._received_bytes):
                    message = self._received_bytes.decode('utf-8')
                    dpi_logger.info(f"Hidden message received: {message}")

                    self._refresh_server_state()

            else:
                self._check_for_transmission_request(tcp_seq)

        else:
            dpi_logger.debug("Non-TCP packet. Skipping...")

    def start_sniffing(self):
        iface = search_for_ifaces()

        filter_berk = f"port {Port.HTTP.value} and src host {self._clt_ip} and dst host {self._srv_ip}"
        dpi_logger.info(
            f"* * * Server is listening for hidden transmission on '{iface}' with filter '{filter_berk}' * * *")

        sniff(iface=iface,
              filter=filter_berk,
              prn=self._handle_stego_packet,
              store=False)


if __name__ == "__main__":
    srv = StegoServer(clt_ip="192.168.12.106", srv_ip="192.168.12.4")
    srv.start_sniffing()
