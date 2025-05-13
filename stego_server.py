import socket
import struct

import select


# Функция для вычисления контрольной суммы TCP
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s


# Параметры сервера
server_ip = "192.168.1.100"  # IP сервера (замени на свой)
server_port = 80  # Порт сервера
seq_num = 2000  # Начальный sequence number сервера

# Создаем raw сокет для отправки
s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Создаем raw сокет для приема
s_receive = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s_receive.bind(('0.0.0.0', 0))

print(f"Сервер запущен на {server_ip}:{server_port}")

while True:
    # Ожидаем SYN-пакет
    readable, _, _ = select.select([s_receive], [], [], 5)
    if readable:
        data, addr = s_receive.recvfrom(65535)
        client_ip = addr[0]

        # Распаковываем IP-заголовок
        ip_header = data[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ip_ihl = iph[0] & 0xF
        ip_ihl_bytes = ip_ihl * 4

        # Распаковываем TCP-заголовок
        tcp_header = data[ip_ihl_bytes:ip_ihl_bytes + 20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        client_port = tcph[0]
        client_seq = tcph[3]
        tcp_flags = tcph[5]

        # Проверяем, что это SYN-пакет (flags = 0x02)
        if tcph[1] == server_port and tcp_flags == 0x02:
            print(f"Получен SYN от {client_ip}:{client_port}")

            # Формируем IP-заголовок для SYN-ACK
            ip_ver_ihl = 0x45
            ip_tos = 0
            ip_tot_len = 40
            ip_id = 54321
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_check = 0
            ip_saddr = socket.inet_aton(server_ip)
            ip_dxaddr = socket.inet_aton(client_ip)

            ip_header = struct.pack('!BBHHHBBH4s4s',
                                    ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                                    ip_ttl, ip_proto, ip_check, ip_saddr, ip_dxaddr)

            # Формируем TCP SYN-ACK-заголовок
            tcp_src = server_port
            tcp_dst = client_port
            tcp_seq = seq_num
            tcp_ack_seq = client_seq + 1
            tcp_doff = 5
            tcp_flags = 0x12  # SYN-ACK
            tcp_window = socket.htons(8192)
            tcp_check = 0
            tcp_urg_ptr = 0

            tcp_header = struct.pack('!HHLLBBHHH',
                                     tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                                     (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

            # Псевдозаголовок для контрольной суммы TCP
            pseudo_header = struct.pack('!4s4sBBH',
                                        ip_saddr, ip_dxaddr, 0, socket.IPPROTO_TCP, len(tcp_header))

            # Вычисляем контрольную сумму TCP
            tcp_check = checksum(pseudo_header + tcp_header)
            tcp_header = struct.pack('!HHLLBBHHH',
                                     tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                                     (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

            # Отправляем SYN-ACK
            packet = ip_header + tcp_header
            s_send.sendto(packet, (client_ip, 0))
            print(f"Отправлен SYN-ACK клиенту {client_ip}:{client_port}")

            # Ожидаем ACK
            while True:
                readable, _, _ = select.select([s_receive], [], [], 5)
                if readable:
                    data, addr = s_receive.recvfrom(65535)
                    ip_header = data[:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    ip_ihl = iph[0] & 0xF
                    ip_ihl_bytes = ip_ihl * 4

                    tcp_header = data[ip_ihl_bytes:ip_ihl_bytes + 20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    if (tcph[0] == client_port and tcph[1] == server_port and
                            tcph[5] == 0x10 and tcph[4] == seq_num + 1):  # ACK (flags = 0x10)
                        print(f"Получен ACK от {client_ip}:{client_port}. Handshake завершен!")

                        # (Опционально) Извлечение данных для стеганографии
                        data_offset = ip_ihl_bytes + (tcph[4] >> 2)
                        payload = data[data_offset:]
                        if payload:
                            print(f"Получены данные: {payload}")
                        break
                else:
                    print("ACK не получен, таймаут")
                    break
            break
