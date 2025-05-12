import socket
import socket
import threading
from random import randint
from typing import Any

from bitarray import bitarray
from bitarray.util import int2ba
from scapy.all import sniff
from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, \
    search_for_ifaces, CRC8_FUNC, BYTE_LEN_IN_BITS, CRC_LEN_BYTE, MAGIC_LEN_BYTE, \
    MSG_LEN_BYTE, get_target_mac

conf.debug_dissector = 2

# 2^32 - 1
MAX_TCP_SEQ_NUM = (1 << 32) - 1

DATA_SIZE_IN_BYTES = 2048


class StegoServer:
    def __init__(self):
        self._stego_active = False
        self._server_seq = randint(0, MAX_TCP_SEQ_NUM)
        self._msg_len = 0
        self._captured_bits = bitarray()

        self._packet_cnt = 0
        self._used_seqs = []

        self._srv_ip = None
        self._clt_ip = None

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

    def _handle_transmission_init(self, seq_num, sport):
        dpi_logger.debug(f"Sequence value: {seq_num}")

        # Shift sequence to get magic value
        magic_trimmed = seq_num >> ((MAGIC_LEN_BYTE + MSG_LEN_BYTE) * BYTE_LEN_IN_BITS) & 0xFF
        dpi_logger.debug(f"magic converted: {int2ba(magic_trimmed)}, len {len(int2ba(magic_trimmed))}.")

        # Shift sequence to get msg_len value
        msg_len_trimmed = (seq_num >> (CRC_LEN_BYTE * BYTE_LEN_IN_BITS)) & 0xFFFF
        dpi_logger.debug(f"len converted: {int2ba(msg_len_trimmed)}, len {len(int2ba(msg_len_trimmed))}.")

        seq_base = (seq_num >> CRC_LEN_BYTE * BYTE_LEN_IN_BITS) & 0xFFFFFF
        dpi_logger.debug(f"seq base converted: {int2ba(seq_base)}, len {len(int2ba(seq_base))}.")

        dpi_logger.debug(f"seq num converted: {int2ba(seq_num)}, len {len(int2ba(seq_num))}.")

        # CRC already in last 8 bits
        crc_received = seq_num & 0xFF

        dpi_logger.debug(f"Magic num received: {magic_trimmed}")

        if magic_trimmed == MAGIC_SEQ:
            dpi_logger.packet("* * * Stego channel request detected * * *")
            crc_calculated = CRC8_FUNC(seq_base.to_bytes(MAGIC_LEN_BYTE + MSG_LEN_BYTE, "big"))

            dpi_logger.debug(f"CRC received: {crc_received}, CRC calculated: {crc_calculated}")
            if crc_calculated == crc_received:
                dpi_logger.debug(
                    f"CRC is correct. Accepting transmission of message with length {msg_len_trimmed}")
                dpi_logger.packet(
                    f"Transmission started")

                self._used_seqs.append(MAGIC_SEQ)
                self._packet_cnt += 1
                self._stego_active = True
                self._msg_len = msg_len_trimmed
                self._clt_port = sport

                ip_l = IP(src=self._srv_ip, dst=self._clt_ip)
                tcp_l = TCP(
                    sport=Port.HTTP.value,
                    dport=self._clt_port,
                    flags=TcpFlag.SYN.value | TcpFlag.ACK.value,
                    seq=self._server_seq,
                    ack=seq_num + 1
                )
                mac = get_target_mac(self._clt_ip)
                sa_pkt = Ether(dst=mac) / ip_l / tcp_l
                sendp(sa_pkt)

            else:
                dpi_logger.error("CRC is incorrect. Transmission rejected")
        else:
            dpi_logger.debug(f"Packet with no magic sequence")

    def _handle_stego_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            dpi_logger.debug("Received a packet")
            tcp_layer = packet.getlayer(TCP)
            seq_num = tcp_layer.seq

            # Handle seen packets
            if seq_num in self._used_seqs:
                dpi_logger.debug("Packet's TCP sequence already used, skipping... ")
                return

            # Handle stego init packet
            if tcp_layer.flags == TcpFlag.SYN.value:
                self._handle_transmission_init(seq_num=seq_num, sport=tcp_layer.sport)

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
        self._srv_ip = dst_ip
        self._clt_ip = src_ip
        iface = search_for_ifaces()
        dpi_logger.info(f"* * * Server is listening for hidden transmission on {iface} * * *")
        sniff(iface=iface,
              filter=f"port 80 and src host {src_ip} and dst host {dst_ip}",
              prn=self._handle_stego_packet,
              store=False)

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
