from random import randint

from bitarray import bitarray
from scapy.all import sniff, Raw, sendp
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from custom_logger import dpi_logger
from session_info import Port, TcpFlag, MAGIC_SEQ, \
    search_for_ifaces, CRC8_FUNC, BYTE_LEN_IN_BITS, CRC_LEN_BYTE, MAGIC_LEN_BYTE, \
    MSG_LEN_BYTE, get_target_mac

conf.debug_dissector = 2
MAX_TCP_SEQ_NUM = (1 << 32) - 1


class StegoServer:
    def __init__(self):
        self._stego_active = False
        self._server_seq = randint(0, MAX_TCP_SEQ_NUM)
        self._msg_len = 0
        self._captured_bits = bitarray()
        self._packet_cnt = 0
        self._used_seqs = set()
        self._srv_ip = None
        self._clt_ip = None
        self._clt_port = None
        self._last_ack = 0

    def _send_tcp_pkt(self, flags, seq, ack, payload=b""):
        ip_l = IP(src=self._srv_ip, dst=self._clt_ip)
        tcp_l = TCP(
            sport=Port.HTTP.value,
            dport=self._clt_port,
            flags=flags,
            seq=seq,
            ack=ack
        )
        ether = Ether(dst=get_target_mac(self._clt_ip))
        pkt = ether / ip_l / tcp_l / Raw(load=payload) if payload else ether / ip_l / tcp_l
        sendp(pkt, verbose=False)

    def _handle_transmission_init(self, seq_num, sport, src_ip, dst_ip):
        magic_trimmed = seq_num >> ((MAGIC_LEN_BYTE + MSG_LEN_BYTE) * BYTE_LEN_IN_BITS) & 0xFF
        msg_len_trimmed = (seq_num >> (CRC_LEN_BYTE * BYTE_LEN_IN_BITS)) & 0xFFFF
        seq_base = (seq_num >> CRC_LEN_BYTE * BYTE_LEN_IN_BITS) & 0xFFFFFF
        crc_received = seq_num & 0xFF

        if magic_trimmed == MAGIC_SEQ:
            crc_calculated = CRC8_FUNC(seq_base.to_bytes(MAGIC_LEN_BYTE + MSG_LEN_BYTE, "big"))
            if crc_calculated == crc_received:
                self._used_seqs.add(seq_num)
                self._stego_active = True
                self._msg_len = msg_len_trimmed
                self._clt_port = sport
                self._clt_ip = src_ip
                self._srv_ip = dst_ip

                self._send_tcp_pkt(flags="SA", seq=self._server_seq, ack=seq_num + 1)
                dpi_logger.info(f"[*] Stego SYN-ACK sent: seq={self._server_seq}, ack={seq_num + 1}")
                self._last_ack = seq_num + 1
            else:
                dpi_logger.warning("[-] CRC mismatch, stego rejected")

    def _handle_stego_packet(self, packet):
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        seq_num = tcp.seq
        sport = tcp.sport

        if seq_num in self._used_seqs:
            return

        if tcp.flags == TcpFlag.SYN.value:
            self._handle_transmission_init(seq_num, sport, src_ip, dst_ip)
            return

        # Маскируемся под HTTP, если получен обычный GET
        if tcp.flags & TcpFlag.PSH.value and packet.haslayer(Raw):
            data = packet[Raw].load
            if data.startswith(b"GET"):
                dpi_logger.info("[>] Received normal GET, responding with fake HTTP")
                self._clt_ip = src_ip
                self._clt_port = sport
                self._srv_ip = dst_ip
                fake_http = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"
                self._send_tcp_pkt(flags="PA", seq=self._server_seq, ack=seq_num + len(data), payload=fake_http)
                self._server_seq += len(fake_http)
                return

        if self._stego_active and (tcp.flags & TcpFlag.ACK.value or tcp.flags & TcpFlag.PSH.value):
            self._used_seqs.add(seq_num)
            bit = seq_num & 1
            self._captured_bits.append(bit)
            self._packet_cnt += 1
            dpi_logger.debug(f"[<] Received bit: {bit} ({self._packet_cnt}/{self._msg_len})")

            self._send_tcp_pkt(flags="A", seq=self._server_seq, ack=seq_num + 1)
            self._server_seq += 1
            self._last_ack = seq_num + 1

            if self._packet_cnt >= self._msg_len:
                msg = self._captured_bits.tobytes().decode("utf-8", errors="ignore")
                dpi_logger.warning(f"[!] Message received: '{msg}'")

                self._send_tcp_pkt(flags="FA", seq=self._server_seq, ack=self._last_ack)
                self._server_seq += 1

                # reset state
                self._stego_active = False
                self._captured_bits.clear()
                self._used_seqs.clear()
                self._packet_cnt = 0

        elif tcp.flags & TcpFlag.FIN.value:
            dpi_logger.info("[*] FIN received from client, sending FIN-ACK")
            self._send_tcp_pkt(flags="FA", seq=self._server_seq, ack=seq_num + 1)
            self._server_seq += 1

    def start_sniffing(self, clt_ip="0.0.0.0", srv_ip="0.0.0.0"):
        self._srv_ip = srv_ip
        self._clt_ip = clt_ip
        iface = search_for_ifaces()
        filter_expr = f"tcp port {Port.HTTP.value} and src host {self._clt_ip} and dst host {self._srv_ip}"
        dpi_logger.info(f"[~] Sniffing on {iface} with filter: {filter_expr}")
        sniff(iface=iface, filter=filter_expr, prn=self._handle_stego_packet, store=False)


if __name__ == "__main__":
    srv = StegoServer()
    srv.start_sniffing(clt_ip="192.168.12.106", srv_ip="192.168.12.4")
