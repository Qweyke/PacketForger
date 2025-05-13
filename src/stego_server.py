import socket
import threading
from random import randint
from typing import Any

from bitarray import bitarray
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
        self._clt_port = None
        self._server_socket = None

    def _handle_client_conn(self, conn: socket.socket, addr: Any):
        dpi_logger.info(f"Connection received from {addr}")
        try:
            data = conn.recv(DATA_SIZE_IN_BYTES)
            if not data:
                dpi_logger.info(f"Client {addr} disconnected")
                return
            if b"GET" in data:
                dpi_logger.info(f"[>] Normal HTTP request from {addr}")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n\nOK\n")
            else:
                dpi_logger.info(f"[?] Unknown request from {addr}")
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        finally:
            conn.close()

    def _handle_transmission_init(self, seq_num, sport, src_ip, dst_ip):
        dpi_logger.debug(f"Sequence value: {seq_num}")
        magic_trimmed = seq_num >> ((MAGIC_LEN_BYTE + MSG_LEN_BYTE) * BYTE_LEN_IN_BITS) & 0xFF
        msg_len_trimmed = (seq_num >> (CRC_LEN_BYTE * BYTE_LEN_IN_BITS)) & 0xFFFF
        seq_base = (seq_num >> CRC_LEN_BYTE * BYTE_LEN_IN_BITS) & 0xFFFFFF
        crc_received = seq_num & 0xFF

        dpi_logger.debug(f"Magic: 0x{magic_trimmed:02x}, Msg_len: {msg_len_trimmed}, CRC: 0x{crc_received:02x}")

        if magic_trimmed == MAGIC_SEQ:
            dpi_logger.warning("* * * Stego channel request detected * * *")
            crc_calculated = CRC8_FUNC(seq_base.to_bytes(MAGIC_LEN_BYTE + MSG_LEN_BYTE, "big"))
            if crc_calculated == crc_received:
                dpi_logger.warning(f"CRC correct, accepting msg_len={msg_len_trimmed}")
                self._used_seqs.append(seq_num)
                self._stego_active = True
                self._msg_len = msg_len_trimmed
                self._clt_port = sport
                self._clt_ip = src_ip
                self._srv_ip = dst_ip

                # Отправляем SYN-ACK через сокет
                ip_l = IP(src=self._srv_ip, dst=self._clt_ip)
                tcp_l = TCP(
                    sport=Port.HTTP.value,
                    dport=self._clt_port,
                    flags="SA",
                    seq=self._server_seq,
                    ack=seq_num + 1
                )
                mac = get_target_mac(self._clt_ip)
                sa_pkt = Ether(dst=mac) / ip_l / tcp_l
                sendp(sa_pkt, verbose=False)
                dpi_logger.info("Sent SYN-ACK")
                self._server_seq += 1
            else:
                dpi_logger.error("CRC incorrect, rejecting")
        else:
            dpi_logger.debug("No magic sequence")

    def _handle_stego_packet(self, packet: Packet):
        if packet.haslayer(TCP):
            dpi_logger.debug("Received a packet")
            tcp_layer = packet.getlayer(TCP)
            seq_num = tcp_layer.seq
            src_ip = packet.getlayer(IP).src
            dst_ip = packet.getlayer(IP).dst

            # Handle seen packets
            if seq_num in self._used_seqs:
                dpi_logger.debug("Packet's TCP sequence already used, skipping...")
                return

            # Handle stego init packet
            if tcp_layer.flags == TcpFlag.SYN.value:
                self._handle_transmission_init(seq_num=seq_num, sport=tcp_layer.sport, src_ip=src_ip, dst_ip=dst_ip)

            elif self._stego_active and (tcp_layer.flags == TcpFlag.ACK.value or tcp_layer.flags & TcpFlag.PSH.value):
                self._used_seqs.append(seq_num)
                extracted_bit = seq_num & 1
                self._captured_bits.append(extracted_bit)
                self._packet_cnt += 1
                dpi_logger.debug(f"Extracted bit: {extracted_bit}, packet count: {self._packet_cnt}")

                # Send ACK to PSH
                if tcp_layer.flags & TcpFlag.PSH.value:
                    ip_l = IP(src=self._srv_ip, dst=self._clt_ip)
                    tcp_l = TCP(
                        sport=Port.HTTP.value,
                        dport=self._clt_port,
                        flags="A",
                        seq=self._server_seq,
                        ack=seq_num + len(tcp_layer.payload) + 1
                    )
                    mac = get_target_mac(self._clt_ip)
                    ack_pkt = Ether(dst=mac) / ip_l / tcp_l
                    sendp(ack_pkt, verbose=False)
                    self._server_seq += 1

                if self._packet_cnt == self._msg_len:
                    msg_in_bytes = self._captured_bits.tobytes()
                    message = msg_in_bytes.decode('utf-8')
                    dpi_logger.info(f"Message received: {message}")
                    self._stego_active = False
                    self._captured_bits = bitarray()
                    self._used_seqs.clear()
                    self._packet_cnt = 0
                    self._clt_port = None
        else:
            dpi_logger.debug("Corrupted packet")

    def start_server(self, host="192.168.12.4", port=Port.HTTP.value):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((host, port))
        self._server_socket.listen(5)
        dpi_logger.info(f"[+] Listening on {host}:{port}")

        try:
            while True:
                conn, addr = self._server_socket.accept()
                threading.Thread(target=self._handle_client_conn, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            dpi_logger.warning("\n[!] Initiating shutdown...")
        finally:
            if self._server_socket:
                self._server_socket.close()
                dpi_logger.warning("\n[!] Server is down.")

    def start_sniffing(self, clt_ip: str = "0.0.0.0", srv_ip: str = "0.0.0.0"):
        self._srv_ip = srv_ip
        self._clt_ip = clt_ip
        iface = search_for_ifaces()

        server_thread = threading.Thread(target=self.start_server, args=(self._srv_ip, Port.HTTP.value), daemon=True)
        server_thread.start()

        filter_berk = f"port {Port.HTTP.value} and src host {self._clt_ip} and dst host {self._srv_ip}"
        dpi_logger.info(
            f"* * * Server is listening for hidden transmission on '{iface}' with filter '{filter_berk}' * * *")
        # Начинаем sniffing
        sniff(iface=iface,
              filter=filter_berk,
              prn=self._handle_stego_packet,
              store=False)


if __name__ == "__main__":
    srv = StegoServer()
    srv.start_sniffing(clt_ip="192.168.12.106", srv_ip="192.168.12.4")
