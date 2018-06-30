#!/usr/bin/env python3
from binascii import hexlify
from binascii import unhexlify
import socket
from curve25519 import Private, Public
import nacl.secret
import hmac
import hashlib

def ReadLine(reader):
  data = b''
  while not data.endswith(b'\n'):
    cur = reader.recv(1)
    data += cur
    if cur == b'':
      return data
  return data[:-1]

def WriteLine(writer, msg):
  writer.send(msg + b'\n')

def ReadBin(reader):
  return unhexlify(ReadLine(reader))

def WriteBin(writer, data):
  WriteLine(writer, hexlify(data))

ss = socket.socket()
cs = socket.socket()
ss.connect(('mitm.ctfcompetition.com', 1337))
cs.connect(('mitm.ctfcompetition.com', 1337))

WriteLine(ss, b's')
WriteLine(cs, b'c')
server_public_key = ReadBin(ss)
server_nonce = ReadBin(ss)
client_public_key = ReadBin(cs)
client_nonce = ReadBin(cs)
my_key = ((2 ** 255) - 19 - 1).to_bytes(255, 'little').rstrip(b'\x00')

WriteBin(ss, my_key)
WriteBin(ss, client_nonce)
WriteBin(cs, my_key)
WriteBin(cs, server_nonce)
server_proof = ReadBin(ss)
client_proof = ReadBin(cs)
WriteBin(cs, server_proof)
WriteBin(ss, client_proof)

auth_data = ReadBin(ss)
WriteBin(cs, auth_data)

myPrivateKey = Private()
theirPublicKey = Public(my_key)
sharedKey = myPrivateKey.get_shared_key(theirPublicKey)
mySecretBox = nacl.secret.SecretBox(sharedkey)
print(mySecretBox.decrypt(auth_data))

get_flag_msg = mySecretBox.encrypt(b'getflag')
WriteBin(ss, get_flag_msg)
flag_msg = ReadBin(ss)
print(mySecretBox.decrypt(flag_msg))

ss.close()
cs.close()