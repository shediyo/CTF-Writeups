import os, base64, time, random, string, sys, hashlib, struct, time, socket
from Crypto.Cipher import AES
from Crypto.Hash import *
from mt_inverse import _int32, temper, MT19937, untemper

def recv_until(s, tr):
    RECV_AMOUNT = 4096
    all_data = ''
    in_data = s.recv(RECV_AMOUNT)
    while tr not in in_data:
        all_data += in_data
        in_data = s.recv(RECV_AMOUNT)
    all_data += in_data
    return all_data


def proof_of_work(s, proof_start):
    z = string.ascii_letters+string.digits
    for c1 in z:
        for c2 in z:
            for c3 in z:
                for c4 in z:
                    check_digest = hashlib.sha256(proof_start + c1 + c2 + c3 + c4).hexdigest()
                    if check_digest.startswith('00000'):
                        send_s = c1 + c2 + c3 + c4
                        print send_s
                        print hashlib.sha256(proof_start + send_s).hexdigest()
                        s.sendall(send_s + '\n')
                        return


def encrypt_msg(s, msg):
    s.sendall('1' + '\n')
    recv_until(s, "give me a string: ")
    s.sendall(msg + '\n')
    answer = recv_until(s, '> ')
    return answer.split('\n')[0].decode('hex')

def get_flag(s):
    s.sendall('3' + '\n')
    answer = recv_until(s, '> ')
    return answer.split('\n')[0].decode('hex')


def main():

    print
    print "Connect and solve POW"
    print

    s = socket.socket()
    s.connect(('206.189.32.108', 13579))
    
    get_msg = recv_until(s, '> ')
    print get_msg
    
    str_prefix = get_msg.split('prefix = ')[1].split('\n')[0]
    print repr(str_prefix)

    real_prefix =  str_prefix.decode('hex')

    proof_of_work(s, real_prefix)
    recv_until(s, '> ')
    

    print
    print "Get all random bits from POW + IV's in encryptions, then untemper"
    print

    vs = []

    gh2 = struct.unpack('>I', real_prefix[0:4])[0]
    gh1 = struct.unpack('>I', real_prefix[4:8])[0]
    for p in [gh1, gh2]:
        vs.append(p)

    for i in range(208):
        if i % 16 == 0:
            print i
        z = encrypt_msg(s, 'h')
        gh4 = struct.unpack('>I', z[0:4])[0]
        gh3 = struct.unpack('>I', z[4:8])[0]
        gh2 = struct.unpack('>I', z[8:12])[0]
        gh1 = struct.unpack('>I', z[12:16])[0]
        for p in [gh1, gh2, gh3, gh4]:
            vs.append(p)
    
    mt_state = []
    for i in xrange(len(vs)):
        mt_state.append(untemper(vs[i]))

    print
    print "Check if had success in getting the MT state"
    print

    mt2 = MT19937(0)
    mt2.mt = mt_state[-624:]
    for i in range(4):
        print 'check',  i
        z = encrypt_msg(s, 'h')
        guesses = []
        real_values = []
        for j in range(4):
            gh = struct.unpack('>I', z[4 * j:4 * j + 4])[0]
            real_values.append(gh)
            guesses.append(mt2.extract_number())         
        for j in range(4):
            print guesses[3 - j]
            print real_values[j]

    print
    print "Save important data - the flag encryption, my message encryption and all MT values"
    print

    fenc = get_flag(s)
    print len(fenc)
    print 'flag enc', repr(fenc)
    f = open('flag_enc.bin', 'wb')
    f.write(fenc)
    f.close()

    my_enc = encrypt_msg(s, 'holy_moly_guakamoly')
    print len(fenc)
    print 'my enc', repr(my_enc)
    f = open('my_enc.bin', 'wb')
    f.write(my_enc)
    f.close()

    z = open('MT_state_value.txt', 'w')
    for m in mt_state:
        z.write(str(m) + '\n')
    z.close()



main()