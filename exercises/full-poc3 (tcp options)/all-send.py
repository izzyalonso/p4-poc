import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1], 8256))

data = bytearray(sys.argv[2], encoding="utf-8")

s.send(data)
data = s.recv(4096).decode()
print data


s.close()

