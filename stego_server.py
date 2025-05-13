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
server_ip = "192.168.12.4"
server_port = 80
seq_num = 2000

# Создаем raw сокет для отправки
try:
    s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except PermissionError:
    print("Ошибка: Запустите с правами администратора")
    exit(1)

# Создаем raw сокет для приема
try:
    s_receive = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except PermissionError:
    print("Ошибка: Запустите с правами администратора")
    exit(1)

print(f"Сервер запущен на {server_ip}:{server_port}")

while True:
    readable, _, _ = select.select([s_receive], [], [], 5)
    if readable:
        data, addr = s_receive.recvfrom(65535)
        client_ip = addr[0]

        # Распаковываем IP-заголовок
        ip_header = data[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ip_ihl = iph[0] & 0xF
        ip_ihl_bytes = ip_ihl * 4
        dest_ip = socket.inet_ntoa(iph[9])

        if dest_ip != server_ip:
            continue

        # Распаковываем TCP-заголовок
        tcp_header = data[ip_ihl_bytes:ip_ihl_bytes + 20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        client_port = tcph[0]
        dest_port = tcph[1]
        client_seq = tcph[3]
        tcp_flags = tcph[5]

        # Проверяем SYN-пакет
        if dest_port == server_port and tcp_flags == 0x02:
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
            ip_daddr = socket.inet_aton(client_ip)

            ip_header = struct.pack('!BBHHHBBH4s4s',
                                    ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                                    ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

            # Формируем TCP SYN-ACK-заголовок
            tcp_src = server_port
            tcp_dst = client_port
            tcp_seq = seq_num
            tcp_ack_seq = client_seq + 1
            tcp_doff = 5
            tcp_flags = 0x12  # SYN-ACK
            tcp_window = 8192  # В пределах 0-65535
            tcp_check = 0
            tcp_urg_ptr = 0

            tcp_header = struct.pack('!HHLLBBHHH',
                                     tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                                     (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

            # Псевдозаголовок для контрольной суммы
            pseudo_header = struct.pack('!4s4sBBH',
                                        ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
            tcp_check = checksum(pseudo_header + tcp_header)
            tcp_header = struct.pack('!HHLLBBHHH',
                                     tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
                                     (tcp_doff << 4), tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

            # Отправляем SYN-ACK
            s_send.sendto(ip_header + tcp_header, (client_ip, 0))
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
                    dest_ip = socket.inet_ntoa(iph[9])

                    if dest_ip != server_ip:
                        continue

                    tcp_header = data[ip_ihl_bytes:ip_ihl_bytes + 20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    if (tcph[0] == client_port and tcph[1] == server_port and
                            tcph[5] == 0x10 and tcph[4] == seq_num + 1):
                        print(f"Получен ACK от {client_ip}:{client_port}. Handshake завершен!")
                        data_offset = ip_ihl_bytes + (tcph[4] >> 2)
                        payload = data[data_offset:]
                        if payload:
                            print(f"Стеганография: данные = {payload}")
                        # Пример стеганографии через window size
                        window_size = tcph[6]
                        print(f"Стеганография: window_size бит = {'0' if window_size % 2 == 0 else '1'}")
                        break
                else:
                    print("ACK не получен, таймаут")
                    break
            break
