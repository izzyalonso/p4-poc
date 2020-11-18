import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

data = bytearray(sys.argv[2], encoding="utf-8")

s.sendto(data, (sys.argv[1], 8256))
buf, addr = s.recvfrom(4096)
data = bytearray()
data.extend(buf)

print data.decode()

f_out = open("h1_in.txt", "w")
f_out.write(data.decode())
f_out.close()

s.close()

