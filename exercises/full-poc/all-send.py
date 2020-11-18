import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = 'localhost'
port = 8254
s.connect((host,port))

data = bytearray()
data.append(10)
data.append(0)
data.append(1)
data.append(1)

address = "%d.%d.%d.%d" % (data[0], data[1], data[2], data[3])
print address

s.send(data)

s.close()

