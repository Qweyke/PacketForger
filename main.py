import sys
from enum import Enum

from scapy.all import sniff
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from custom_logger import dpi_logger

HST_IP = "192.168.12.4"
DST_IP = "192.168.12.14"
SRC_IP = "192.168.12.13"


class Port(Enum):
    HTTP = 80
    HTTPS = 443
    SSH = 22


class DpiAnalyzer:
    def __init__(self):
        self._packet_cnt = 0

        self._current_iface = None
        self._iface_list = []
        self._search_for_ifaces()

    def _search_for_ifaces(self):

        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):

            # Try to find ip on net iface
            ips = iface.get('ips', [])
            mac = iface.get('mac', None)
            if ips and mac and len(ips) > 0:
                dpi_logger.info(f"[{i}] {iface.get('name', 'N/A')}")
                dpi_logger.info(f"{iface.get('description', 'N/A')}")

                for ip in ips:
                    dpi_logger.info(ip, sub_lvl="IP")

                dpi_logger.info(f"{mac if mac else 'N/A'}", sub_lvl="MAC")
                dpi_logger.info(f"{iface.get('guid', 'N/A')}", sub_lvl="GUID")
                dpi_logger.info("---------------------------------------------")
                self._iface_list.append(iface)

    def _parse_packet_http(self, packet):
        def encode_flag(flags: int) -> str:
            flag_names = {
                0x01: "FIN",
                0x02: "SYN",
                0x04: "RST",
                0x08: "PSH",
                0x10: "ACK",
                0x20: "URG",
                0x40: "ECE",
                0x80: "CWR"
            }

            result = [name for bit, name in flag_names.items() if flags & bit]
            return "|".join(result) if result else "NONE"

        self._packet_cnt += 1
        dpi_logger.packet(f"Packet [{self._packet_cnt}]")

        dpi_logger.packet(
            f"From {packet.getlayer(IP).src if packet.haslayer(IP) else 'N/A'}:{packet.getlayer(TCP).sport if packet.haslayer(TCP) else 'N/A'}"
        )
        dpi_logger.packet(
            f"To {packet.getlayer(IP).dst if packet.haslayer(IP) else 'N/A'}:{packet.getlayer(TCP).dport if packet.haslayer(TCP) else 'N/A'}"
        )

        dpi_logger.packet(
            f"Packet type: {encode_flag(packet.getlayer(TCP).flags) if packet.haslayer(TCP) else 'N/A'}")

        payload = packet[Raw].load if packet.haslayer(Raw) else None
        if payload:
            body_raw = None

            try:
                # Check header/data delimiter in payload
                if b"\r\n\r\n" in payload:
                    header_raw, body_raw = payload.split(b"\r\n\r\n", 1)
                    header_str = header_raw.decode("utf-8", errors="replace")

                else:
                    header_str = payload.decode("utf-8", errors="replace")

                for line in header_str.split("\r\n"):
                    dpi_logger.packet(line)

            except Exception as e:
                dpi_logger.error(f"Header parsing error: {e}")

            dpi_logger.packet(f"Data: {'True' if body_raw else 'False'}")

        dpi_logger.info("------------------------------------------------------")

    def choose_iface_for_sniffing(self):
        dpi_logger.info("Enter interface number to sniff: ")
        iface_num = input().strip()
        self._current_iface = self._iface_list[int(iface_num)]

    def start_sniffing(self):
        dpi_logger.info("Sniffing started")
        iface_name = self._current_iface.get('name')
        sniff(iface=iface_name,
              # filter=f"tcp port {Port.HTTP.value} and (host {DST_IP} or host {SRC_IP} or host {HST_IP})",
              filter=f"host {DST_IP} or host {SRC_IP} or host {HST_IP}",
              prn=self._parse_packet_http, store=False)


if __name__ == "__main__":
    try:
        analyzer = DpiAnalyzer()

        analyzer.choose_iface_for_sniffing()
        analyzer.start_sniffing()

    except Exception as ex:
        dpi_logger.info(f"Exception: {ex}")
        sys.exit(1)
