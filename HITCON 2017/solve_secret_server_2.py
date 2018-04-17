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

# flag: hitcon{uNp@d_M3th0D_i5_am4Z1n9!}
def main():
    # server
    s = socket.socket()
    s.connect(CONN_ADDR)

    # proof of work
    get_msg = recv_until(s, 'Give me XXXX')
    print get_msg
    proof_end = get_msg.split('XXXX+')[1].split(')')[0]
    digest = get_msg.split('== ')[1].split('\n')[0]
    print repr(proof_end)
    print repr(digest)
    proof_of_work(s, proof_end, digest)

    # forge get token of welcome msg
    welcome_msg = s.recv(4096)
    welcome_msg = welcome_msg.replace('\n', '')
    welcome_msg = base64.b64decode(welcome_msg)
    get_token_msg = iv_replacer(welcome_msg, 'Welcome!!', 'get-token')
    get_token_msg_e = base64.b64encode(get_token_msg)
    s.sendall(get_token_msg_e + '\n')
    print repr(get_token_msg)
    print len(get_token_msg)

    # get the token encrypted msg
    token_msg = s.recv(4096)
    token_msg += s.recv(4096)
    token_msg = token_msg.replace('\n', '')
    token_msg = base64.b64decode(token_msg)
    print 'token msg:'
    print repr(token_msg)
    print len(token_msg)

    # make just a regular get-md5 message to encrypt several length
    get_md5_msg = iv_replacer(welcome_msg[:], 'Welcome', 'get-md5') 
    get_md5_start = get_md5_msg[:32] * 3

    # prepare computations of 64 md5's, of padding 32-96
    md5_saved = []
    for i in range(64):
        pad_msg = get_md5_msg[:15] + chr(ord(get_md5_msg[15]) ^ 7 ^ (32 + i)) + get_md5_msg[16:32]
        get_md5_msg_e = base64.b64encode(get_md5_start[:] + pad_msg)
        s.sendall(get_md5_msg_e + '\n')  
        print 'check off ' + str(i) + ':' 

        md5_got_msg = s.recv(4096)
        md5_got_msg += s.recv(4096)
        md5_got_msg = md5_got_msg.replace('\n', '')
        md5_got_msg = base64.b64decode(md5_got_msg)
        print 'md5 got msg:'
        print repr(md5_got_msg)
        print len(md5_got_msg)

        md5_saved += [md5_got_msg]

    # bad command prep
    s.sendall(base64.b64encode(welcome_msg[:]) + '\n')
    bad_command = s.recv(4096)
    bad_command += s.recv(4096)
    bad_command = bad_command.replace('\n', '')
    bad_command = base64.b64decode(bad_command)
    print 'bad comm msg:'
    print repr(bad_command)
    print len(bad_command)

    # token start msg
    token_start_msg = iv_replacer(token_msg[:], 'token: ', 'get-md5') 

    # padding offsets
    START_PAD_LEN = 64 + 16 * 2 - 8
    END_PAD_LEN = 16 * 2 - 1
    candidates = ['']

    # main calculation
    for pad_len in range(START_PAD_LEN, END_PAD_LEN, -1):
        # calculate encrypted md5(calculated_data + new_char)
        new_token_msg = get_token_msg[:15] + chr(ord(get_token_msg[15]) ^ pad_len ^ 7) + get_token_msg[16:]
        send_msg = token_start_msg + new_token_msg
        send_msg = base64.b64encode(send_msg)
        s.sendall(send_msg + '\n')
        ans_msg = s.recv(4096)
        ans_msg += s.recv(4096)
        print 'got answer for padding length ' + str(pad_len) + ':'
        ans_msg = ans_msg.replace('\n', '')
        ans_msg = base64.b64decode(ans_msg)[:32]
        print repr(ans_msg)

        concluded = False
        md5_char = '\x00'

        # 4 options to xor into 32-96 padding length - check each to fall into calculated area
        for (xor_val1, xor_val2) in [(0,0), (0, 128), (32, 0), (32, 128)]:
            check_msg = get_md5_start[:] + ans_msg[:15] + chr(ord(ans_msg[15]) ^ (xor_val2 ^ xor_val1)) + ans_msg[16:] 
            check_msg = base64.b64encode(check_msg)
            s.sendall(check_msg + '\n')

            check_ans_msg = s.recv(4096)
            check_ans_msg += s.recv(4096)
            check_ans_msg = check_ans_msg.replace('\n', '')
            check_ans_msg = base64.b64decode(check_ans_msg)
            print repr(check_ans_msg)

            if check_ans_msg != bad_command:
                print 'not bad'
                for b in range(64):
                    if check_ans_msg == md5_saved[b]:
                        md5_char = chr((b + 32) ^ xor_val2 ^ xor_val1)
                        concluded = True
                        print ord(md5_char)
                if concluded:
                    break
            else:
                print 'bad'

        # should not happen 
        if not concluded:
            print 'shit'
            return
        
        # calculate new candidates by checking their last md5 char
        new_candidates = []
        for cand in candidates:
            for guess in range(256):
                if MD5.new(cand + chr(guess)).digest()[15] == md5_char:
                    new_candidates.append(cand + chr(guess))
        candidates = new_candidates[:]
        print 'candidates'
        print [repr(x) for x in candidates]
        print len(candidates)
        print len(candidates[0])

    # last candidates swipe by padding in the end
    new_candidates = []
    for cand in candidates:
        if cand[-1] == '\x01':
            new_candidates += [cand[:-1]]

    # should remain only one
    candidates = new_candidates[:]
    print [repr(x) for x in candidates]
    print len(candidates)
    print len(candidates[0])

    # get flag through checking token
    check_token_msg = iv_replacer(welcome_msg[:], 'Welcome!!' + '\x07' * 7, 'check-token' + '\x05' * 5)
    check_token_msg = base64.b64encode(check_token_msg)
    s.sendall(check_token_msg + '\n') 
    send_token = base64.b64encode(candidates[0])
    s.sendall(send_token + '\n') 
    for i in range(5):
        print s.recv(4096)