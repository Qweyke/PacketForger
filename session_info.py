import os
import platform
from enum import Enum

from bitarray import bitarray
from bitarray.util import ba2int
from crcmod import crcmod

from custom_logger import dpi_logger


def generate_magic_seq(byte_len: int):
    test = 233
    random_bytes = os.urandom(byte_len)
    # To big endian int
    magic_seq = int.from_bytes(random_bytes, byteorder='big')
    dpi_logger.debug(f"Seq seed is: {magic_seq}")
    dpi_logger.debug(f"Seq test seed is: {test}")

    return test


class Port(Enum):
    HTTP = 80
    HTTPS = 443
    SSH = 22


class TcpFlag(Enum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


MSG_LEN_BYTE = 16
TCP_HEADER_SEQ_LEN_BYTE = 4
BYTE_LEN_IN_BITS = 8

CRC = bitarray("111010101")
CRC_INT = ba2int(CRC)
# Must be changed for diff CRC type
CRC_LEN_BYTE = BYTE_LEN_IN_BITS

MAGIC_SEQ = generate_magic_seq(1)
MAGIC_LEN_BYTE = len(MAGIC_SEQ.to_bytes())

CRC8_FUNC = crcmod.mkCrcFun(CRC_INT, initCrc=0x0, rev=False, xorOut=0x0)


def search_for_ifaces():
    iface_list = []
    if platform.system() == "Windows":
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        for i, iface in enumerate(interfaces):
            ips = iface.get('ips', [])
            mac = iface.get('mac', None)
            if ips and mac and len(ips) > 0:
                dpi_logger.info(f"[{i}] {iface.get('name', 'N/A')}")
                dpi_logger.info(f"{iface.get('description', 'N/A')}")
                for ip in ips:
                    dpi_logger.info(ip, sub_lvl="IP")
                dpi_logger.info(f"{mac if mac else 'N/A'}", sub_lvl="MAC")
                dpi_logger.info(f"{iface.get('guid', 'N/A')}", sub_lvl="GUID")
                iface_list.append(iface)
                dpi_logger.info("---------------------------------------------")


    else:
        from scapy.interfaces import get_if_list
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            dpi_logger.info(f"[{i}] Interface: {iface}")
            iface_list.append(iface)

    dpi_logger.info("Enter interface number to sniff: ")
    iface_num_inp = input().strip()
    iface_to_return = iface_list[int(iface_num_inp)].get("name") if platform.system() == "Windows" else iface_list[
        int(iface_num_inp)]

    print(iface_to_return)

    return iface_to_return


if __name__ == "__main__":
    search_for_ifaces()
