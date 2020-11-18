import socket
import sys


def deal_with_connection(connection):
    data = bytearray()
    while True:
        buf = connection.recv(4096)
        data.extend(buf)
        
        if len(buf) < 4096:
            break
    
    f_out = open("h3_in.txt", "w")
    f_out.write(data.decode())
    f_out.close()
    
    out_string = "Hello, %d" % data.decode()
    out_data = bytearray(out_string, encoding="utf-8")
    
    connection.send(out_data)
    


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('10.0.3.3', 8256))
sock.listen(1)

while True:
    try:
        connection, clientAddress = sock.accept()
        deal_with_connection(connection)
        connection.close()
    except Exception:
        break;

sock.close()


