import argparse

from scapy.all import sniff
from scapy.layers.inet import TCP


def bits_to_text(bits):
    """Преобразование битовой строки в текст."""
    chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)


def extract_message(packet):
    """Извлечение сообщения из пакета."""
    global captured_bits
    if packet.haslayer(TCP):
        # Извлекаем младший бит Sequence Number
        bit = packet[TCP].seq & 1
        captured_bits.append(str(bit))

        # Если собрано достаточно битов (кратно 8), пытаемся декодировать
        if len(captured_bits) >= 8 and len(captured_bits) % 8 == 0:
            message = bits_to_text(''.join(captured_bits))
            print(f"Извлечённое сообщение: {message}")


def start_sniffing(src_ip, dst_ip, src_port, dst_port, count):
    """Захват пакетов и извлечение сообщения."""
    global captured_bits
    captured_bits = []

    filter_str = f"tcp and host {src_ip} and host {dst_ip} and port {src_port} and port {dst_port}"
    print(f"Начало захвата пакетов (максимум {count} пакетов)...")

    sniff(filter=filter_str, prn=extract_message, count=count, store=False)

    if captured_bits:
        message = bits_to_text(''.join(captured_bits))
        print(f"Финальное извлечённое сообщение: {message}")
    else:
        print("Сообщение не извлечено: пакеты не захвачены.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Извлечение сообщения из TCP Sequence Numbers.")
    parser.add_argument("--src-ip", default="192.168.12.13", help="IP-адрес отправителя")
    parser.add_argument("--dst-ip", default="192.168.12.14", help="IP-адрес получателя")
    parser.add_argument("--src-port", type=int, default=12345, help="Порт отправителя")
    parser.add_argument("--dst-port", type=int, default=80, help="Порт получателя")
    parser.add_argument("--count", type=int, default=40, help="Количество пакетов для захвата")

    args = parser.parse_args()

    start_sniffing(args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.count)
