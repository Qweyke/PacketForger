import socket
import threading
from typing import Any

from bitarray import bitarray
from scapy.all import sniff
from scapy.config import conf
from scapy.layers.inet import TCP
from scapy.packet import Packet

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, \
    search_for_ifaces, CRC8_FUNC, BYTE_LEN_IN_BITS, CRC_LEN_BYTE, MAGIC_LEN_BYTE, TCP_HEADER_SEQ_LEN_BYTE

conf.debug_dissector = 2

DATA_SIZE_IN_BYTES = 2048


class StegoServer:
    def __init__(self):
        self._stego_active = False
        self._msg_len = 0
        self._captured_bits = bitarray()

        self._packet_cnt = 0
        self._used_seqs = []

    def _handle_client_conn(self, conn: socket.socket, addr: Any):
        dpi_logger.info(f"Connection received from {addr}")
        try:
            data = conn.recv(DATA_SIZE_IN_BYTES)

            if not data:
                dpi_logger.info(f"Client {addr} disconnected ")
                return

            if b"GET" in data:
                dpi_logger.info(f"[>] Normal HTTP request from {addr}")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n\nOK\n")

            else:
                print(f"[?] Unknown request from {addr}")
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        finally:
            conn.close()

    def _handle_stego_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            seq_num = tcp_layer.seq

            if seq_num in self._used_seqs:
                dpi_logger.warning("Used seq handled")
                return

            if tcp_layer.flags == TcpFlag.SYN.value:
                # seq_num &= 0xFFFFFFFF
                # Get magic num
                magic = (seq_num >> ((MAGIC_LEN_BYTE + CRC_LEN_BYTE) * BYTE_LEN_IN_BITS)) & 0xFF
                # Get len val
                msg_len = (seq_num >> (CRC_LEN_BYTE * BYTE_LEN_IN_BITS)) & 0xFFFF
                # Crc is in the end already
                crc = seq_num & 0xFF

                dpi_logger.info(f"Magic num: {magic}")
                seq_bytes = seq_num.to_bytes(TCP_HEADER_SEQ_LEN_BYTE, "big")

                if magic == MAGIC_SEQ:
                    dpi_logger.warning("Hidden session request detected")
                    crc_output = CRC8_FUNC(seq_bytes)
                    dpi_logger.info(f"CRC: {crc_output}")
                    if crc_output == 0:
                        dpi_logger.warning("CRC correct")
                        self._used_seqs.append(MAGIC_SEQ)
                        self._packet_cnt += 1
                        self._stego_active = True
                        self._msg_len = msg_len
                        dpi_logger.info(f"Msg len: {self._msg_len}")
                    else:
                        dpi_logger.error("CRC incorrect")

                # elif self._stego_active and tcp_layer.flags & TcpFlag.PSH.value:
                #
                #     self._used_seqs.append(seq_num)
                #     bit = seq_num & 1
                #     self._captured_bits.append(bit)
                #
                #     self._packet_cnt += 1
                #
                #     # Assemble header of hidden msg first
                #     if len(self._captured_bits) >= STEGO_HEAD_MSG_LEN:
                #         dpi_logger.info(f"Header assembled: {self._captured_bits[:16].to01()}")
                #         dpi_logger.info(f"Data body: {self._captured_bits[16:].to01()}")
                #         if len(self._captured_bits) >= STEGO_HEAD_MSG_LEN + int(self._captured_bits[16:].tobytes()):
                #             # decrypted_bits = self.decrypt_bits(''.join(self.captured_bits), "secret")
                #             message = self._captured_bits[16:].tobytes().decode("utf-8")
                #             print(f"Extracted message: {message}")
                #
                #             self._stego_active = False
                #             self._captured_bits = bitarray()
                #             self._used_seqs.clear()
                #             self._packet_cnt = 0

                else:
                    dpi_logger.warning(f"No magic seq")

        else:
            dpi_logger.debug("Corrupted packet")

    def start_server(self, host, port=Port.HTTP.value):
        # Create OS net socket with params
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind it to our ip:port for listening
        server.bind((host, port))

        # Listen for 5 clients in queue, 6th will get a reject
        server.listen(5)

        dpi_logger.info(f"[+] Listening on {host}:{port}")

        try:

            while True:
                # Wait for client to connect
                conn, addr = server.accept()
                # Handle client
                threading.Thread(target=self._handle_client_conn, args=(conn, addr), daemon=True).start()


        except KeyboardInterrupt:
            dpi_logger.warning("\n[!] Initiating shutting down...")
        finally:
            server.close()
            dpi_logger.warning("\n[!] Server is down.")

    def start_sniffing(self, src_ip: str = "0.0.0.0", dst_ip: str = "0.0.0.0"):
        iface = search_for_ifaces()
        sniff(iface=iface,
              filter=f"port 80 and src host {src_ip} and dst host {dst_ip}",
              prn=self._handle_stego_packet,
              store=False)
        
        dpi_logger.info("Stego server is listening * * *")

        # def sniff_fun():
        #     try:
        #
        #     except Exception as e:
        #         dpi_logger.error(f"Sniffing failed: {e}")
        #
        # threading.Thread(target=sniff_fun, daemon=True).start()


if __name__ == "__main__":
    srv = StegoServer()
    srv.start_sniffing(src_ip="192.168.12.106", dst_ip="192.168.12.4")
    # srv.start_server(host=HST_IP)
