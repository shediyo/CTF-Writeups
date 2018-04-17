import socket
import time
import struct

import os, base64, time, random, string
from Crypto.Cipher import AES
from Crypto.Hash import *

CONN_ADDR = ('52.193.157.19', 9999)
CONN_ADDR = ('52.192.29.52', 9999)
# CONN_ADDR = ('192.168.132.129', 9999)

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
 

def proof_of_work(s, proof_end, digest):
    z = string.ascii_letters+string.digits
    for c1 in z:
        for c2 in z:
            for c3 in z:
                for c4 in z:
                    check_digest = SHA256.new(c1 + c2 + c3 + c4 + proof_end).hexdigest()
                    if check_digest == digest:
                        print 'Found'
                        s.sendall(c1 + c2 + c3 + c4 + '\n')
                        return

def iv_replacer(iv_msg, before_replace, after_replace):
    cut = len(before_replace)
    xor_vals = [ord(before_replace[i]) ^ ord(after_replace[i]) for i in range(cut)]
    iv_msg = ''.join([chr(ord(iv_msg[i]) ^ xor_vals[i]) for i in range(cut)]) + iv_msg[cut:]
    return iv_msg

# flag: hitcon{Paddin9_15_ve3y_h4rd__!!}
def main():
    s = socket.socket()
    s.connect(CONN_ADDR)
    
    get_msg = recv_until(s, 'Give me XXXX')
    print get_msg
    
    proof_end = get_msg.split('XXXX+')[1].split(')')[0]
    digest = get_msg.split('== ')[1].split('\n')[0]
    print repr(proof_end)
    print repr(digest)
    proof_of_work(s, proof_end, digest)

    print recv_until(s, 'Done!')
    
    welcome_msg = s.recv(4096)
    welcome_msg = welcome_msg.replace('\n', '')
    msg = base64.b64decode(welcome_msg)
    get_flag_msg = iv_replacer(msg, 'Welcome!!', 'get-flagg')
    get_flag_msg_e = base64.b64encode(get_flag_msg)
    s.sendall(get_flag_msg_e + '\n')
    print repr(get_flag_msg)
    print len(get_flag_msg)

    flag_msg = s.recv(4096)
    flag_msg = flag_msg.replace('\n', '')
    flag_msg = base64.b64decode(flag_msg)
    print 'flag:'
    print repr(flag_msg)
    print len(flag_msg)

    start_msg = iv_replacer(flag_msg[:], 'hitcon{', 'get-md5')
    print 'start as flag:'
    print repr(start_msg)
    print len(start_msg)


    # see padding
    START_PAD_LEN = 48 + 16 * 2 - 7
    END_PAD_LEN = 16 * 2
    collected_str = ''
    for pad_len in range(START_PAD_LEN - 1, END_PAD_LEN, -1):
        new_flag_msg = get_flag_msg[:]
        new_flag_msg = new_flag_msg[:15] + chr(ord(new_flag_msg[15]) ^ pad_len ^ 7) + new_flag_msg[16:]
        send_msg = start_msg + new_flag_msg
        send_msg = base64.b64encode(send_msg)
        s.sendall(send_msg + '\n')

        ans_msg = s.recv(4096)
        ans_msg += s.recv(4096)
        print 'answer'
        print repr(ans_msg)
        ans_msg = ans_msg.replace('\n', '')
        ans_msg = base64.b64decode(ans_msg)
        print repr(ans_msg)

        for t in string.ascii_letters+string.digits + ' []:;*+=/?>.<,-{}_\'`"\\|\n\r@#$!%^&*()':
            z = t
            print 'guess', z
            check_msg = iv_replacer(ans_msg ,MD5.new(collected_str + z).digest()[:8], 'get-flag')
            check_msg = base64.b64encode(check_msg)
            s.sendall(check_msg + '\n')

            flag_ans_msg = s.recv(4096)
            flag_ans_msg += s.recv(4096)
            flag_ans_msg = flag_ans_msg.replace('\n', '')
            flag_ans_msg = base64.b64decode(flag_ans_msg)
            if flag_ans_msg == flag_msg:
                collected_str += z
                print 'found'
                break
        print 'c-str:'
        print collected_str

main()
