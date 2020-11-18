import socket
import sys
import struct


def deal_with_connection(connection):
    data = bytearray()
    while True:
        buf = connection.recv(4096)
        data.extend(buf)
        
        if len(buf) < 4096:
            break
    
    address = "%d.%d.%d.%d" % (data[0], data[1], data[2], data[3])
    
    original_data = data
    
    data = data[4:]
    
    f_out = open("h2_in.txt", "w")
    f_out.write(original_data.decode())
    f_out.write("\n%s (%d, %d) -> %s" % (address, len(original_data), len(data), data.decode()))
    f_out.close()
    
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.connect((address,8256))
    # s.send(data)
    # buf = s.recv(4096)
    # data = bytearray()
    # data.extend(buf)
    # s.close()
    
    connection.send(data)
    


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


