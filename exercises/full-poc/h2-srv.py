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
    print address
    


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = ('localhost', 8254)
sock.bind(address)
sock.listen(1)

while True:
    connection, clientAddress = sock.accept()
    deal_with_connection(connection)

