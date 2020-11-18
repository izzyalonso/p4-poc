import socket
import sys


def deal_with_connection(connection):
    data = bytearray()
    while True:
        buf = connection.recv(4096)
        data.extend(buf)
        
        if len(buf) < 4096:
            break
    
    address = "%d.%d.%d.%d" % (data[0], data[1], data[2], data[3])
    
    f_out = open("h2_in.txt", "w")
    f_out.write(data.decode())
    f_out.close()
    
    print address
    
    #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #s.connect((address,8254))
    #s.send(data)
    #s.close()
    


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('localhost', 8256)
sock.bind(address)
sock.listen(1)

while True:
    try:
        connection, clientAddress = sock.accept()
        deal_with_connection(connection)
        connection.close()
    except Exception:
        break;

sock.close()


