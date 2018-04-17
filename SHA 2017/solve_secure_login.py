import socket
import time

n = 25504352309535290475248970674346405639150033303276037621954645287836414954584485104061261800020387562499019659311665606506084209652278825297538342995446093360707480284955051977871508969158833725741319229528482243960926606982225623875037437446029764584076579733157399563314682454896733000474399703682370015847387660034753890964070709371374885394037462378877025773834640334396506494513394772275132449199231593014288079343099475952658539203870198753180108893634430428519877349292223234156296946657199158953622932685066947832834071847602426570899103186305452954512045960946081356967938725965154991111592790767330692701669
e = 65537

def num2str(n):
    d = ('%x' % n)
    if len(d) % 2 == 1:
        d = '0' + d
    return d.decode('hex')

def str2num(s):
    return int(s.encode('hex'),16)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
    
def get_user_ticket(s, user, fn):
    s.send('1')
    time.sleep(0.3)
    s.recv(4096)
    s.send(user)
    time.sleep(0.1)
    s.recv(1024)
    s.send(fn)
    time.sleep(0.3)
    home = s.recv(4096)
    print 'received data' + repr(home)
    answer = home.split('\n')[1]
    print "signed encoded:" + repr(answer)
    signed = answer.decode('hex')
    print "signed:" + repr(signed)
    signed_num = str2num(signed)
    print "signed num:" + repr(str(signed_num))
    return signed_num
    
def get_signature(s, message):
    challenge = message[1:].encode('hex')
    print 'message:', repr(message)
    print 'sending data:', challenge
    s.send('3')
    time.sleep(0.3)
    s.recv(4096)
    s.send(challenge)
    time.sleep(0.1)
    s.recv(1024)
    time.sleep(0.3)
    home = s.recv(4096)
    print repr(home)
    print "pasten\n\n\n"
    answer = home.split('\n')[0]
    print "signed encoded:" + repr(answer)
    signed = answer.decode('hex')
    print "signed:" + repr(signed)
    signed_num = str2num(signed)
    print "signed num:" + repr(str(signed_num))
    return signed_num
    
def send_ticket(s, ticket_num_signed):
    print 'data:', ticket_num_signed
    print 'data 2:', hex(ticket_num_signed)[:-1]
    print 'data 3:', int(hex(ticket_num_signed)[:-1], 16)
    s.send('2')
    time.sleep(0.3)
    print s.recv(4096)
    s.send(hex(ticket_num_signed)[:-1])
    time.sleep(0.1)
    print s.recv(1024)
    time.sleep(0.3)
    home = s.recv(4096)
    print home

def break_ticket():
    s = socket.socket()
    s.connect(('secure-login.stillhackinganyway.nl', 12345))
    wanted = 'ticket:admin|root|p'
    wanted_num = str2num(wanted)
    my_mult = 0
    message = ''
    
    for multi in range(2 ** 16):
        mult_message = (wanted_num * pow(multi, e, n)) % n 
        if num2str(mult_message)[0] == '\xff':
            my_mult = multi
            message = num2str(mult_message)
            break
            
    print my_mult
    
    # let the games begin
    time.sleep(0.3)
    s.recv(4096)
    # ticket_signed = get_user_ticket(s, 'user', 'fn')
    num = get_signature(s, message)
    ticket_signed = (num * modinv(my_mult, n)) % n
    send_ticket(s, ticket_signed)

break_ticket()
