import os, base64, time, random, string, sys, hashlib, struct, time, socket
from Crypto.Cipher import AES
from Crypto.Hash import *
from mt_inverse import _int32, temper, MT19937, untemper

def to_string(num, max_len = 128):
    tmp = bin(num).lstrip('0b')[-max_len:].rjust(max_len, '0')
    return "".join(chr(int(tmp[i:i+8], 2)) for i in range(0, max_len, 8))

def pad(s):
    bs = 16
    padnum = bs - len(s) % bs
    return s + padnum * chr(padnum)


def broken_random(first_val, second_val):
    a = first_val >> 5
    b = second_val > >6
    return ( a * 67108864.0 + b ) * ( 1.0 / 9007199254740992.0 )


def find_possible_states_from_known(known_mt_state):
    possible_states = []
    for lowest_bits in range(2 ** 8):
        mt_state = known_mt_state[:]
        for j in range(-1, 8):
            mt_state = [0] + mt_state
            current_lowest = (lowest_bits >> j) % 2 if j != -1 else mt_state[1] % 2 
            backwards_state = ( (mt_state[624] ^ mt_state[397] ^ (current_lowest * 0x9908b0df) ) << 1 ) & 0xFFFFFFFF
            mt_state[1] = ((highest_bit << 31) + (backwards_state & 0x7fffffff) + current_lowest) & 0xFFFFFFFF if j != -1 else mt_state[1]
            highest_bit = backwards_state >> 31 
        possible_states.append(mt_state[1:9])

    real_possible_states = []
    for possible_state in possible_states:
        possible_mt = MT19937(0)
        possible_mt.mt = possible_state + known_mt_state[:624 - 8]
        possible_mt.index = 0
        possible_extended_state = []

        known_mt = MT19937(0)
        known_mt.mt = known_mt_state[:624]
        known_mt.index = 0
        known_extended_state = []

        for i in range(624 + 8 + 624 * 3):
            possible_extended_state.append(possible_mt.extract_number())
        for i in range(624 + 624 * 3):
            known_extended_state.append(known_mt.extract_number())
        if possible_extended_state[8:] == known_extended_state:
            real_possible_states.append(possible_state)

    return real_possible_states



def main():
    flag_data = open('flag_enc.bin', 'rb').read()
    flag_iv = flag_data[:16]
    flag_enc_msg = flag_data[16:]

    my_enc_data = open('my_enc.bin', 'rb').read()
    my_enc_iv = my_enc_data[:16]
    my_enc_msg = my_enc_data[16:]

    mt_state_lines = open('MT_state_value.txt', 'r').readlines()
    known_mt_state = [int(m[:-1]) for m in mt_state_lines]
    possible_states = find_possible_states_from_known(known_mt_state)
    assert len(possible_states) == 2

    possible_keys = []
    for mt_state in possible_states:
        tmp1 = broken_random(_int32(temper(mt_state[0])), _int32(temper(mt_state[1])))
        tmp2 = broken_random(_int32(temper(mt_state[2])), _int32(temper(mt_state[3])))
        pre_key_1 = int(tmp1 * 2**128) | int(tmp2 * 2**75)

        tmp3 = broken_random(_int32(temper(mt_state[4])), _int32(temper(mt_state[5])))
        tmp4 = broken_random(_int32(temper(mt_state[6])), _int32(temper(mt_state[7])))
        pre_key_2 = int(tmp3 * 2**128) | int(tmp4 * 2**75)

        possible_keys.append((pre_key_1, pre_key_2))

    meet_in_middle = [{}, {}]

    print 'Starting meet in the middle attack'

    for mask1 in range(0x3fffff + 1):
        if mask1 % (2 ** 16) == 0:
            print mask1
        for j in range(2):
            key = to_string(possible_keys[j][0] | mask1)
            aes = AES.new(key, AES.MODE_CBC, my_enc_iv)
            msg = aes.decrypt(my_enc_msg)
            meet_in_middle[j][msg[:8]] = key

    print 'Store done, now search'

    for mask2 in range(0x3fffff + 1):
        if mask2 % (2 ** 16) == 0:
            print mask2
        for j in range(2):
            key2 = to_string(possible_keys[j][1] | mask2)
            aes2 = AES.new(key2, AES.MODE_CBC, my_enc_iv)
            msg = aes2.encrypt(pad('holy_moly_guakamoly'))
            if msg[:8] in meet_in_middle[j]:
                key1 = meet_in_middle[j][msg[:8]]
                aes1 = AES.new(key1, AES.MODE_CBC, flag_iv)
                aes2 = AES.new(key2, AES.MODE_CBC, flag_iv)
                real_msg = aes2.decrypt(aes1.decrypt(flag_enc_msg))
                if 'MeePwn' in real_msg:
                    print real_msg
                    return
        
main()

























# def random_logic_test():
#     random.getrandbits(32)
#     fir_st = random.getstate()

#     breaks = False
#     sec_st = ''
#     i = 0
#     while not breaks:
#         z = random.getrandbits(32)
#         sec_st = random.getstate()
#         if sec_st[1][:624] != fir_st[1][:624]:
#             print i
#             breaks = True
#         i += 1

#     thr_st = ''
#     breaks = False
#     i = 0
#     while not breaks:
#         z = random.getrandbits(32)
#         thr_st = random.getstate()
#         if thr_st[1][:624] != sec_st[1][:624]:
#             print i
#             breaks = True
#         i += 1

#     the_check_state = list(fir_st[1][:8])
#     print the_check_state

#     known_mt_state = list(fir_st[1][8:624]) + list(sec_st[1][:624]) + list(thr_st[1][:624])
#     print len(known_mt_state)

#     possible_states = find_possible_states_from_known(known_mt_state)
#     print possible_states
#     print the_check_state in possible_states

#     print random.random()
#     st = random.getstate()
#     ind, state = st[1][624], st[1]
#     print random.random()
#     print broken_random(_int32(temper(state[ind % 624])), _int32(temper(state[(ind + 1) % 624])))