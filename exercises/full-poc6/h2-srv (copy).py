import socket
import sys


def deal_with_connection(connection):
    data = bytearray()
    while True:
        buf = connection.recv(4096)
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
    
    connection.send(data)
    


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.0.2.2', 8256))
sock.listen(1)

while True:
    try:
        connection, clientAddress = sock.accept()
        deal_with_connection(connection)
        connection.close()
    except Exception:
        break

sock.close()


