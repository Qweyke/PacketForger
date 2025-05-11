import os
from enum import Enum

from bitarray import bitarray
from crcmod import crcmod

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


MAX_HEADER_LEN = 16
TCP_HEADER_SEQ_LEN = 32
BYTE_LEN = 8
BYTE_MASK = 0xFF

CRC = bitarray("1101")
CRC_LEN = len(CRC)

HST_IP = "192.168.12.4"

SRV_IP = "192.168.12.14"
CLT_IP = "192.168.12.13"


def generate_magic_seq(byte_len: int):
    random_bytes = os.urandom(byte_len)
    # To big endian int
    magic_seq = int.from_bytes(random_bytes, byteorder='big')
    dpi_logger.debug(f"Seq seed is: {magic_seq}")
    return magic_seq


# Cunning number for steganograpy transmission
MAGIC_SEQ = generate_magic_seq(1)
MAGIC_SEQ_LEN = len(MAGIC_SEQ.to_bytes()) * BYTE_LEN

CRC4_FUNC = crcmod.mkCrcFun(CRC, initCrc=0x0, rev=False, xorOut=0x0)
