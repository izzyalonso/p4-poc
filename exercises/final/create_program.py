import string

template_file = open('templates/edge_template.p4', mode='r')
template_string = template_file.read()
template_file.close()

# For 1

my_host_ip = "8w10++8w0++8w1++8w1"
my_host_mac = "8w8++8w0++8w0++8w0++8w1++8w0x11"


# For 2
"""
my_host_ip = "8w10++8w0++8w2++8w2"
my_host_mac = "8w8++8w0++8w0++8w0++8w2++8w0x22"
"""

next_hop_mac = "8w8++8w0++8w0++8w0++8w3++8w0"

template = string.Template(template_string)
prog = template.substitute(
    my_host_ip=my_host_ip,
    my_host_mac=my_host_mac,
    next_hop_mac=next_hop_mac,
    addresses="",
    ports="",
    incoming_rules="",
    outgoing_rules=""
)

out = open("s1.p4", "w")
out.write(prog)
out.close()

