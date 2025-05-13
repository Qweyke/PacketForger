import socket
import struct

import select


# Функция для вычисления контрольной суммы (для TCP)
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


# Параметры
src_ip = "192.168.12.106"  # Твой IP
dst_ip = "192.168.12.4"  # IP сервера (замени на реальный IP, например, "93.184.216.34")
src_port = 122345  # Любой порт
dst_port = 80  # Порт сервера
seq_num = 1000  # Начальный sequence number

# Создаем raw сокет
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Формируем IP-заголовок для SYN
ip_ver_ihl = 0x45  # Версия 4, длина заголовка 20 байт
ip_tos = 0
ip_tot_len = 40  # IP header (20) + TCP header (20)
ip_id = 54321
ip_frag_off = 0
ip_ttl = 64
ip_proto = socket.IPPROTO_TCP
ip_check = 0  # Ядро заполнит
ip_saddr = socket.inet_aton(src_ip)
ip_daddr = socket.inet_aton(dst_ip)

ip_header = struct.pack('!BBHHHBBH4s4s',
                        ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# Формируем TCP SYN-заголовок
tcp_src = src_port
tcp_dst = dst_port
tcp_seq = seq_num
tcp_ack_seq = 0
tcp_doff = 5  # Длина заголовка в 32-битных словах (5 * 4 = 20 байт)
tcp_flags = 0x02  # SYN flag
tcp_window = socket.htons(8192)
tcp_check = 0
tcp_urg_ptr = 0

tcp_header = struct.pack('!HHLLBBHHH',
                         tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                         (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

# Псевдозаголовок для контрольной суммы TCP
pseudo_header = struct.pack('!4s4sBBH',
                            ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))

# Вычисляем контрольную сумму TCP
tcp_check = checksum(pseudo_header + tcp_header)
tcp_header = struct.pack('!HHLLBBHHH',
                         tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                         (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

# Собираем и отправляем SYN-пакет
packet = ip_header + tcp_header
s.sendto(packet, (dst_ip, 0))

# Создаем сокет для захвата SYN-ACK
s_receive = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s_receive.bind(('0.0.0.0', 0))

# Ожидаем SYN-ACK
while True:
    readable, _, _ = select.select([s_receive], [], [], 5)
    if readable:
        data, addr = s_receive.recvfrom(65535)
        # Распаковываем IP-заголовок
        ip_header = data[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ip_ihl = iph[0] & 0xF
        ip_ihl_bytes = ip_ihl * 4

        # Распаковываем TCP-заголовок
        tcp_header = data[ip_ihl_bytes:ip_ihl_bytes + 20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        if tcph[0] == dst_port and tcph[1] == src_port and tcph[5] == 0x12:  # SYN-ACK (flags = 0x12)
            server_seq = tcph[3]
            server_ack = tcph[4]
            break

# Формируем ACK-пакет
tcp_seq = seq_num + 1
tcp_ack_seq = server_seq + 1
tcp_flags = 0x10  # ACK flag
tcp_header = struct.pack('!HHLLBBHHH',
                         tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                         (tcp_doff << 4), tcp_flags, tcp_window, 0, tcp_urg_ptr)

pseudo_header = struct.pack('!4s4sBBH',
                            ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
tcp_check = checksum(pseudo_header + tcp_header)
tcp_header = struct.pack('!HHLLBBHHH',
                         tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                         (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

# Собираем и отправляем ACK-пакет
packet = ip_header + tcp_header
s.sendto(packet, (dst_ip, 0))

print("TCP handshake завершен!")

# if __name__ == "__main__":
#     clt = StegoClient()
#     clt.send_stego_msg("hi", clt_ip="192.168.12.106", srv_ip="192.168.12.4")
