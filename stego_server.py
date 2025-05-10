import socket
import threading
from typing import Any

from bitarray import bitarray
from scapy.layers.inet import TCP
from scapy.packet import Packet

from custom_logger import dpi_logger
from session_info import Port, HST_EXT_IP, TcpFlag, MAGIC_SEQ

DATA_SIZE_IN_BYTES = 2048
STEGO_HEAD_MSG_LEN = 16


class StegoServer:
    def __init__(self):
        self._stego_active = False
        self._captured_bits = bitarray()
        # self._active_session = ()

    def handle_client_conn(self, conn: socket.socket, addr: Any):
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

    def handle_stego_packet(self, packet: Packet):
        segments_cnt = 0
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer.flags == TcpFlag.SYN.value and tcp_layer.seq == MAGIC_SEQ:
                dpi_logger.warning("Hidden session request detected")
                self._stego_active = True

            elif self._stego_active and tcp_layer.flags & TcpFlag.PSH.value:
                bit = packet[TCP].seq & 1
                self._captured_bits.append(bit)
                # Check receiv
                if len(self._captured_bits) >= STEGO_HEAD_MSG_LEN:
                    length = int(''.join(self.captured_bits[:16]), 2)
                    if len(self.captured_bits) >= 16 + length:
                        decrypted_bits = self.decrypt_bits(''.join(self.captured_bits), "secret")
                        message = self.bits_to_text(decrypted_bits[16:16 + length])
                        print(f"Extracted message: {message}")
                        self.stego_active = False
                        self.captured_bits = []

        else:
            dpi_logger.debug("Corrupted packet")

    def start_server(self, host=HST_EXT_IP, port=Port.HTTP.value):
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
                threading.Thread(target=self.handle_client_conn, args=(conn, addr), daemon=True).start()


        except KeyboardInterrupt:
            dpi_logger.warning("\n[!] Initiating shutting down...")
        finally:
            server.close()
            dpi_logger.warning("\n[!] Server is down.")


if __name__ == "__main__":
    srv = StegoServer()
    srv.start_server()
