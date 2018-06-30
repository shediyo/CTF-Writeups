#!/usr/bin/env python3
import functools
import struct
import socket

from not_des import KEY_SIZE, BLOCK_SIZE, IP, IP_INV, E, PC1_C, PC1_D, PC2, KS_SHIFTS, P, SBOXES
from not_des import Xor, Concat, Str2Bits, Bits2Str, Expand, LeftShift, KeyScheduler, DESEncrypt, DESDecrypt, CipherFunction

def rec_preimage_cipher(stage, first_val, second_val, val_32, val_1, key):
  sbox_inp = [-1, -1, -1, -1, -1, -1]
  sbox_inp[0], sbox_inp[1] = first_val, second_val

  for i in range(2 ** 4):
    sbox_inp[2], sbox_inp[3] = (i % 2), ((i // 2) % 2)
    sbox_inp[4] = val_32 if stage == 7 else ((i // 4) % 2)
    sbox_inp[5] = val_1 if stage == 7 else ((i // 8) % 2)
    keyed_sbox_inp = [0] * 6
    for j in range(6):
      keyed_sbox_inp[j] = sbox_inp[j] ^ key[stage // 4] 
    sbox = SBOXES[stage]
    row = (int(keyed_sbox_inp[0]) << 1) + int(keyed_sbox_inp[-1])
    col = int(''.join([str(b) for b in keyed_sbox_inp[1:5]]), 2)

    if sbox[row][col] == 0:
      if stage == 7:
        return sbox_inp
      mid_res = rec_preimage_cipher(stage + 1, sbox_inp[4], sbox_inp[5], val_32, val_1, key)
      if mid_res is not None:
        return sbox_inp + mid_res
        
  return None

def preimage_cipher():
  chosen_input = None
  final_key = None
  for key in [(0,0), (0,1), (1,0), (1,1)]:
    for t in [(0,0), (0,1), (1,0), (1,1)]:
      res = rec_preimage_cipher(0, t[0], t[1], t[0], t[1], key)
      if res is not None:
        chosen_input = res
        final_key = key
        break

  if chosen_input is None:
    return None, None

  final_preimage_bits = []
  for i in range(8):
    final_preimage_bits += chosen_input[6 * i + 2: 6 * i + 6]
  final_preimage_bits = [final_preimage_bits[-1]] + final_preimage_bits[:-1]
  final_preimage_bytes = [int('0b' + ''.join(str(b) for b in final_preimage_bits[8 * i: 8 * i + 8]), 2) for i in range(4)]
  final_preimage = bytes(final_preimage_bytes * 2)
  final_key = bytes([0xff if final_key[0] == 1 else 0] * 4 + [0xff if final_key[1] == 1 else 0] * 4)

  return final_preimage, final_key

def main():
  # FLAG: CTF{7h3r35 4 f1r3 574r71n6 1n my h34r7 r34ch1n6 4 f3v3r p17ch 4nd 175 br1n61n6 m3 0u7 7h3 d4rk}
  preimage_input, preimage_key = preimage_cipher()
  if preimage_input is None:
    print("FAIL")
    return
  print(preimage_input)
  print(preimage_key)

  # Needed conversions
  preimage_input = Str2Bits(preimage_input)
  preimage_input = [preimage_input[IP_INV[i] - 1] for i in range(64)]
  preimage_input = Bits2Str(preimage_input)

  preimage_key = Str2Bits(preimage_key)
  for i in range(28):
    preimage_key[PC1_C[i] - 1] = 1
    preimage_key[PC1_D[i] - 1] = 0
  preimage_key = Bits2Str(preimage_key)

  print("Preimage Check")
  print(preimage_input)
  print(preimage_key)
  print(DESEncrypt(preimage_input, preimage_key))

  # Unused bits easy collision
  collision_input = bytes(b'0' * 8)
  collision_key_1 = bytes([0xff] * 8)
  collision_key_2 = bytes([0xfe] + [0xff] * 7)

  s = socket.socket()
  s.connect(('dm-col.ctfcompetition.com',1337))
  s.send(collision_key_1)
  s.send(collision_input)
  s.send(collision_key_2)
  s.send(collision_input)
  s.send(preimage_key)
  s.send(preimage_input)
  print(s.recv(2048))

main()
