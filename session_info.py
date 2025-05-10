import os
from enum import Enum

from custom_logger import dpi_logger


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


HST_IP = "127.0.0.1"
HST_EXT_IP = "192.168.12.4"
SRV_IP = "192.168.12.14"
CLT_IP = "192.168.12.13"


def generate_magic_seq32():
    random_bytes = os.urandom(4)
    # To big endian int
    magic_seq = int.from_bytes(random_bytes, byteorder='big')
    dpi_logger.debug(f"Seq seed is: {magic_seq}")
    return magic_seq


# Cunning number for steganograpy transmission
MAGIC_SEQ = generate_magic_seq32()
