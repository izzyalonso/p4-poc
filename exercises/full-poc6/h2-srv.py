import socket
import sys


def deal_with_connection(in_sock):
    data = bytearray()
    while True:
        buf, addr = in_sock.recvfrom(4096)
        data.extend(buf)
        
        if len(buf) < 4096:
            break
    
    f_out = open("h2_in.txt", "w")
    f_out.write(data.decode())
    f_out.close()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.0.3.3', 8257))
    s.send(data)
    buf = s.recv(4096)
    data = bytearray()
    data.extend(buf)
    s.close()
    
    in_sock.sendto(data, addr)
    


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.0.2.2', 8256))

while True:
    try:
        deal_with_connection(sock)
    except Exception:
        break

sock.close()


