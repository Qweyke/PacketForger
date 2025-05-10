import sys

from scapy.arch.windows import get_windows_if_list

from custom_logger import dpi_logger
from encoder import forge_packet

iface_list = []


def search_for_ifaces():
    interfaces = get_windows_if_list()
    for i, iface_dict in enumerate(interfaces):
        ips = iface_dict.get('ips', [])
        mac = iface_dict.get('mac', None)
        if ips and mac and len(ips) > 0:
            dpi_logger.info(f"[{i}] {iface_dict.get('name', 'N/A')}")
            dpi_logger.info(f"{iface_dict.get('description', 'N/A')}")
            for ip in ips:
                dpi_logger.info(ip, sub_lvl="IP")
            dpi_logger.info(f"{mac if mac else 'N/A'}", sub_lvl="MAC")
            dpi_logger.info(f"{iface_dict.get('guid', 'N/A')}", sub_lvl="GUID")
            dpi_logger.info("---------------------------------------------")
            iface_list.append(iface_dict)


def choose_iface_for_sniffing():
    dpi_logger.info("Enter interface number to sniff: ")
    iface_num = input().strip()
    return iface_list[int(iface_num)]


if __name__ == "__main__":
    try:
        iface = choose_iface_for_sniffing()
        forge_packet(net_iface=iface.get("name", "none"), msg="fuck me")


    except Exception as ex:
        dpi_logger.info(f"Exception: {ex}")
        sys.exit(1)
