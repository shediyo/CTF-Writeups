import socket
import time
import struct

CONN_ADDR = ('13.112.220.64', 9999)
SLEEP_TIME = 0.3
FAST_SLEEP_TIME = 0.05
RECV_AMOUNT = 4096

#N = 104176920808444707134363566789644103637046138703732812593856489450966164422700871083271001476798525601830292237723021138499045286505397665962198734248957208942814238767855960753797521549548788530151996440657784060736603682776712677518537991291065233449586393186516770855075158900503486179189610821817031409223
    
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

def one_of_list_in(lst, dat):
    return (True in [z in dat for z in lst])

def recv_until_either(s, tr_list):
    all_data = ''
    in_data = s.recv(RECV_AMOUNT)
    while not one_of_list_in(tr_list, in_data):
        all_data += in_data
        in_data = s.recv(RECV_AMOUNT)
    all_data += in_data
    return all_data
    
def recv_until(s, tr):
    all_data = ''
    in_data = s.recv(RECV_AMOUNT)
    while tr not in in_data:
        all_data += in_data
        in_data = s.recv(RECV_AMOUNT)
    all_data += in_data
    return all_data
    
def send_string(s, wstr):
    s.sendall(wstr)
    time.sleep(SLEEP_TIME)
    
def send_int(s, choice):
    s.sendall(str(choice))
    time.sleep(SLEEP_TIME)
    
def send_int_fast(s, choice):
    s.sendall(str(choice))
    time.sleep(FAST_SLEEP_TIME)

def are_arrays_the_same_permutation(arr_1, arr_2):
    return sorted(arr_1) == sorted(arr_2)
 

def get_enc_data(s, files_to_enc):
    for i in range(len(files_to_enc)):
        print '\n\n\niteration: ', str(i)
        send_string(s, files_to_enc[i])
        get_enc = recv_until(s, 'filename(txt)')
        if 'error' in get_enc:
            continue
        msg = get_enc.split('Input')[0].split('Result: ')[1]
        print msg
        print '----'
        enc_data = long(msg)
        print enc_data
        print '----'
        return enc_data

def main():
    file_to_dec = 'flag'
    s = socket.socket()
    s.connect(CONN_ADDR)
    
    get_msg = recv_until(s, 'filename(txt)')
    print get_msg
    
    N = get_msg.split('e:')[0].split('N: ')[1].strip()
    print N
    print 'len of N:', len(N)
    e = 3
    N = sum([int(c) * ((10) ** i) for i, c in enumerate(N[::-1])])
    print '----'
    print N
    print '----\n\n\n'

    files_to_enc = [file_to_dec + '\x00' * 11]
    c_3 = get_enc_data(s, files_to_enc)

    files_to_enc = ['z' * 13 + '\x00' * 2]
    files_to_enc += ['z' * 15]
    files_to_enc += [file_to_dec + '\x00' * 11]
    c_116 = get_enc_data(s, files_to_enc)

    g,a,b = egcd(3, 116)
    if a < 0:
        c_3 = modinv(c_3, N) % N
        a = -a
    if b < 0:
        c_116 = modinv(c_116, N) % N
        b = -b
    m = (pow(c_3, a, N) * pow(c_116, b, N)) % N
    print m
    print '------------------\n\n\n\n\n'
    print repr(''.join([chr( (m / (256 ** i)) % 256 ) for i in range(100)])[::-1])


    
main()
'''
c_116 = 34015050739171424314498710560698933245290487498407796325442619137486729442802528626382281472580331765072329760653988415330996610121722917108068295306759509236079670592756017946213660204166698063720347903421975796238572540763828405967122388498856634690437707718068681935013304774553910859857042301346162679298

c_3 = 80026450605919212347157319516655228661982088106956311148514121800139890113377161068043879513015347037232410178041918490832353137735848626795271143817272105057902549455690557715462777567966903851646207028020678373050285949287173514737755698953051536123368646144531895984034141177000138932645546381541544731963

g,a,b = egcd(3, 116)

print a,b

m = (pow(c_3, a, N) * modinv(c_116, N)) % N

print ''.join([chr( (m / (256 ** i)) % 256 ) for i in range(80)])[::-1]
'''
