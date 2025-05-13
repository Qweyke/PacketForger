import os
import platform
import re
from enum import Enum

from bitarray import bitarray
from bitarray.util import ba2int
from crcmod import crcmod
from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

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


TCP_SEQ_BYTE_LEN = 32

MSG_LENGTH_BYTE_LEN = 16
BASE_BYTE_LEN = 16

DATA_BYTE_LEN = 8
CRC_BYTE_LEN = 8

CRC = bitarray("111010101")
CRC_INT = ba2int(CRC)
# Must be changed for diff CRC type


MAGIC_SEQ = generate_magic_seq(1)
MAGIC_BYTE_LEN = len(MAGIC_SEQ.to_bytes()) * 8

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

    return iface_to_return


# https://github.com/secdev/scapy/issues/4473
def get_target_mac(dst_ip: str):
    """Get the dest MAC for the IP."""
    # First check if it's in our arp table
    mac = None
    dst_ip_re = re.compile(r"^.*" + re.escape(dst_ip) + r".*$", re.IGNORECASE)
    with os.popen("arp -a") as fh:
        lines = fh.read().splitlines()
    for line in lines:
        if dst_ip_re.match(line):
            try:
                mac = line.split()[1].strip().replace("-", ":")
            except:
                pass
            break
    if mac:
        return mac

    default_gw = conf.route.route("0.0.0.0")[2]
    arp = ARP(pdst=dst_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    attempt = 0
    while attempt < 3:
        try:
            ans = srp(packet, timeout=2, verbose=False)[0]
            mac = ans[0][1].hwsrc
            return mac
        except:
            pass
        attempt += 1

    # Probably not on the LAN - Use gateway
    arp = ARP(pdst=default_gw)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    attempt = 0
    while attempt < 3:
        try:
            ans = srp(packet, timeout=2, verbose=False)[0]
            mac = ans[0][1].hwsrc
            return mac
        except:
            pass
        attempt += 1

    # Unable to determine dest MAC
    dpi_logger.warning(f"Unable to determine dest MAC for {dst_ip}. Using broadcast.")
    return "ff:ff:ff:ff:ff:ff"


if __name__ == "__main__":
    search_for_ifaces()
