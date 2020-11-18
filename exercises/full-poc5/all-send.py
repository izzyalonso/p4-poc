import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1],8256))

data = bytearray(sys.argv[2], encoding="utf-8")

s.send(data)
buf = s.recv(4096)
data = bytearray()
data.extend(buf)

print data.decode()

f_out = open("h1_in.txt", "w")
f_out.write(data.decode())
f_out.close()

s.close()

